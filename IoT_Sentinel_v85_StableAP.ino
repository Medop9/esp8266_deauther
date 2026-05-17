/*
 * ============================================================
 *  IoT Sentinel v8.5 — Stable-AP + Captive Portal Build
 *  Network Intrusion Detection System  (24/7 Automatic)
 *  Elmaghraoui Mouad & Youssef Boutayeb | EIDIA UEMF 2025
 * ------------------------------------------------------------
 *  Fixes vs v8.4:
 *   1. WiFi scan stays in AP_STA - AP no longer dies on refresh
 *   2. DNSServer captive portal - phone keeps the link forever
 *   3. CPD endpoints (Android / Apple / Windows / Samsung)
 *   4. Non-blocking scan state machine
 *   5. Reliable Referer-based redirect (collectHeaders)
 *   6. Cooperative network probe (yields to web server)
 * ============================================================
 */

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <WiFiClientSecure.h>
#include <UniversalTelegramBot.h>
#include <ArduinoJson.h>
#include <EEPROM.h>

extern "C" {
  #include "lwip/etharp.h"
  #include "lwip/netif.h"
  #include "lwip/ip4_addr.h"
}

// --- credentials ------------------------------------------------------------
#define BOT_TOKEN "8779703712:AAHHR9TS0nPrlh1CkGANejKROGRQ2IHzQeQ1"
#define CHAT_ID   "5401312485"
const char* AP_SSID = "IoT-Sentinel";
const char* AP_PASS = "sentinel2025";

// --- pinout -----------------------------------------------------------------
#define LED_SAFE    14   // D5
#define LED_SUSPECT 12   // D6
#define LED_DANGER  13   // D7
#define BUZZER      15   // D8  (must be LOW at boot, active buzzer OK)

// --- limits -----------------------------------------------------------------
#define MAX_DEV    30
#define MAX_WL     25
#define MAX_BL     25
#define MAX_LOG    20
#define MAX_NETS   20
#define SCAN_MS    90000UL
#define TIMEOUT_MS 600000UL
#define PROBE_MS   300
#define TELE_LIMIT 20000UL
#define WIFI_CACHE 60000UL    // wifi-scan cache TTL
#define DNS_PORT   53

// --- data structures --------------------------------------------------------
struct Device {
  char          mac[18];
  char          ip[16];
  char          prevIP[16];
  char          brand[24];
  unsigned long lastSeen;
  unsigned long firstSeen;
  bool          trusted;
  bool          blocked;
  int           blockHits;
};

Device devs[MAX_DEV];
int    devCount = 0;

String wl[MAX_WL]; int wlN = 0;
String bl[MAX_BL]; int blN = 0;

int           threatLevel = 0;
String        threatMAC   = "";
String        threatIP    = "";
String        threatInfo  = "";

String        aLog[MAX_LOG];
unsigned long aTime[MAX_LOG];
int           aCount = 0;
int           totalA = 0;

// --- LAN scan progress ------------------------------------------------------
bool          scanning = false;
int           scanProg = 0;
bool          staMode  = false;

char          cfgSSID[64] = "";
char          cfgPASS[64] = "";

unsigned long t0        = 0;
unsigned long tLastScan = 0;
unsigned long tLastBuzz = 0;
unsigned long tLastTele = 0;

// --- WiFi-AP scan state machine --------------------------------------------
enum WifiScanState { WS_IDLE, WS_REQUESTED, WS_RUNNING, WS_DONE };
volatile WifiScanState wifiScanState = WS_IDLE;

String        scanSSIDs[MAX_NETS];
int           scanRSSIs[MAX_NETS];
uint8_t       scanEncs [MAX_NETS];
uint8_t       scanChans[MAX_NETS];
int           scanCount = 0;
unsigned long scanCacheTime = 0;

// --- web stack --------------------------------------------------------------
ESP8266WebServer     srv(80);
DNSServer            dnsServer;
WiFiClientSecure     teleClient;
UniversalTelegramBot bot(BOT_TOKEN, teleClient);

// ================================================================
//                       OUI VENDOR DATABASE
// ================================================================
struct OUI { const char* id; const char* name; };
const OUI ouiDB[] PROGMEM = {
  {"3C15B2","Apple"},{"ACB73A","Apple"},{"F8278B","Apple"},
  {"7C6D62","Apple"},{"881FA1","Apple"},{"001124","Apple"},
  {"001451","Apple"},{"203D5F","Apple"},{"28CF92","Apple"},
  {"34159E","Apple"},{"4C57CA","Apple"},{"90C682","Apple"},
  {"A45E60","Apple"},{"B418D1","Apple"},{"F0DCE2","Apple"},
  {"002339","Samsung"},{"1C62B8","Samsung"},{"286D97","Samsung"},
  {"34AA8B","Samsung"},{"38AA3C","Samsung"},{"40F720","Samsung"},
  {"44784F","Samsung"},{"60014E","Samsung"},{"68DBCA","Samsung"},
  {"78595E","Samsung"},{"A0B4A5","Samsung"},{"B4EF39","Samsung"},
  {"BCCCED","Samsung"},{"CC07AB","Samsung"},{"E86F38","Samsung"},
  {"001E10","Huawei"},{"0C37DC","Huawei"},{"107BCE","Huawei"},
  {"243C20","Huawei"},{"2C55D3","Huawei"},{"30D175","Huawei"},
  {"341A91","Huawei"},{"548998","Huawei"},{"58605F","Huawei"},
  {"68A0F6","Huawei"},{"6CB3A6","Huawei"},{"70721E","Huawei"},
  {"900B40","Huawei"},{"945FEC","Huawei"},{"98E703","Huawei"},
  {"006006","Xiaomi"},{"14F65A","Xiaomi"},{"286C07","Xiaomi"},
  {"2C4412","Xiaomi"},{"34CE00","Xiaomi"},{"50EC50","Xiaomi"},
  {"58449F","Xiaomi"},{"64B473","Xiaomi"},{"741331","Xiaomi"},
  {"8CBFB1","Xiaomi"},{"9C99A0","Xiaomi"},{"AC2374","Xiaomi"},
  {"1C5C07","Oppo"},{"2032CA","Oppo"},{"44004D","Oppo"},
  {"5C2E59","Oppo"},{"9CAA83","Oppo"},{"B4CD27","Oppo"},
  {"C808E9","Oppo"},{"E8BBA8","Oppo"},
  {"205D47","Vivo"},{"485DC6","Vivo"},{"5C59A8","Vivo"},
  {"8038BC","Vivo"},{"AC67B2","Vivo"},
  {"94492B","OnePlus"},{"A4C395","OnePlus"},
  {"B4F1DA","OnePlus"},{"D4CABB","OnePlus"},
  {"001422","Dell"},{"001D09","Dell"},{"086B03","Dell"},
  {"18A905","Dell"},{"848F69","Dell"},{"B083FE","Dell"},
  {"001CC0","HP"},{"0021B0","HP"},{"1C98EC","HP"},
  {"204E7F","HP"},{"9CB654","HP"},{"F4CE46","HP"},
  {"001EEC","Lenovo"},{"0021CC","Lenovo"},{"10BEF5","Lenovo"},
  {"28D244","Lenovo"},{"3C970E","Lenovo"},{"484ABD","Lenovo"},
  {"54A44C","Lenovo"},{"74867A","Lenovo"},{"C4697B","Lenovo"},
  {"001A92","Asus"},{"001D60","Asus"},{"10BF48","Asus"},
  {"2C56DC","Asus"},{"485B39","Asus"},{"74D02B","Asus"},
  {"90E6BA","Asus"},{"F8324E","Asus"},
  {"000E5E","ZTE"},{"001E73","ZTE"},{"103D0D","ZTE"},
  {"1C8773","ZTE"},{"200DB0","ZTE"},{"344DEA","ZTE"},
  {"488736","ZTE"},{"507548","ZTE"},{"5C4CA9","ZTE"},
  {"5C6272","ZTE"},{"68DCE5","ZTE"},{"74401A","ZTE"},
  {"B47C9C","ZTE"},{"C4360C","ZTE"},{"D07AB5","ZTE"},
  {"001D0F","TP-Link"},{"14CC20","TP-Link"},{"18A6F7","TP-Link"},
  {"30DE4B","TP-Link"},{"50C7BF","TP-Link"},{"54AF97","TP-Link"},
  {"5C628B","TP-Link"},{"788322","TP-Link"},{"B0487A","TP-Link"},
  {"D8EB97","TP-Link"},{"EC172F","TP-Link"},{"F4F26D","TP-Link"},
  {"18FE34","Espressif"},{"24B2DE","Espressif"},{"2C3AE8","Espressif"},
  {"30AEA4","Espressif"},{"601401","Espressif"},{"807D3A","Espressif"},
  {"84F3EB","Espressif"},{"A020A6","Espressif"},{"A4CF12","Espressif"},
  {"B4E62D","Espressif"},{"E09806","Espressif"},{"FC4480","Espressif"},
  {"B827EB","RaspPi"},{"DCA632","RaspPi"},{"E45F01","RaspPi"},
  {"",""}
};

String getBrand(const char* mac) {
  char oui[7];
  oui[0]=mac[0]; oui[1]=mac[1];
  oui[2]=mac[3]; oui[3]=mac[4];
  oui[4]=mac[6]; oui[5]=mac[7];
  oui[6]='\0';
  for(int i=0;i<6;i++) if(oui[i]>='a') oui[i]-=32;
  for(int i=0; ; i++) {
    char id[7];
    strncpy_P(id, (PGM_P)pgm_read_ptr(&ouiDB[i].id), 6); id[6]='\0';
    if(id[0]=='\0') break;
    if(strncmp(oui,id,6)==0) {
      char nm[24];
      strncpy_P(nm,(PGM_P)pgm_read_ptr(&ouiDB[i].name),23); nm[23]='\0';
      return String(nm);
    }
  }
  return "Unknown";
}

String brandIcon(const String& b) {
  if(b=="Apple")   return "[Apple]";
  if(b=="Samsung"||b=="Xiaomi"||b=="Huawei"||
     b=="Oppo"||b=="Vivo"||b=="OnePlus") return "[Phone]";
  if(b=="Dell"||b=="HP"||b=="Lenovo"||b=="Asus") return "[PC]";
  if(b=="ZTE"||b=="TP-Link") return "[Router]";
  if(b=="Espressif") return "[ESP]";
  if(b=="RaspPi")    return "[RPi]";
  return "[?]";
}

// ================================================================
//                          EEPROM
// ================================================================
#define EE_MAGIC  0xA9
#define EE_SIZE   1040

void eeSave() {
  EEPROM.begin(EE_SIZE);
  EEPROM.write(0, EE_MAGIC);
  for(int i=0;i<63;i++) EEPROM.write(1+i,  cfgSSID[i]);
  for(int i=0;i<63;i++) EEPROM.write(65+i, cfgPASS[i]);
  EEPROM.write(130,(uint8_t)wlN);
  for(int i=0;i<wlN;i++)
    for(int j=0;j<17;j++)
      EEPROM.write(131+i*17+j, j<(int)wl[i].length()?wl[i][j]:0);
  int bo=131+MAX_WL*17;
  EEPROM.write(bo,(uint8_t)blN);
  for(int i=0;i<blN;i++)
    for(int j=0;j<17;j++)
      EEPROM.write(bo+1+i*17+j, j<(int)bl[i].length()?bl[i][j]:0);
  EEPROM.commit();
  EEPROM.end();
}

void eeLoad() {
  EEPROM.begin(EE_SIZE);
  if(EEPROM.read(0)!=EE_MAGIC){
    EEPROM.end();
    Serial.println(F("[EE] Fresh start."));
    return;
  }
  for(int i=0;i<63;i++) cfgSSID[i]=EEPROM.read(1+i);  cfgSSID[63]='\0';
  for(int i=0;i<63;i++) cfgPASS[i]=EEPROM.read(65+i); cfgPASS[63]='\0';
  wlN=min((int)EEPROM.read(130),MAX_WL);
  for(int i=0;i<wlN;i++){
    char m[18]; m[17]='\0';
    for(int j=0;j<17;j++) m[j]=EEPROM.read(131+i*17+j);
    wl[i]=String(m);
  }
  int bo=131+MAX_WL*17;
  blN=min((int)EEPROM.read(bo),MAX_BL);
  for(int i=0;i<blN;i++){
    char m[18]; m[17]='\0';
    for(int j=0;j<17;j++) m[j]=EEPROM.read(bo+1+i*17+j);
    bl[i]=String(m);
  }
  EEPROM.end();
  Serial.printf("[EE] Loaded SSID=%s WL=%d BL=%d\n",cfgSSID,wlN,blN);
}

// ================================================================
//                          UTILS
// ================================================================
void teleAlert(const String& msg, bool force=false) {
  if(!staMode) return;
  if(!force && millis()-tLastTele < TELE_LIMIT) return;
  tLastTele = millis();
  Serial.println(F("[TELE] Sending..."));
  bool ok = bot.sendMessage(CHAT_ID, msg, "Markdown");
  Serial.println(ok ? F("[TELE] OK") : F("[TELE] FAIL"));
}

String uptime() {
  unsigned long s=(millis()-t0)/1000;
  char b[12];
  sprintf(b,"%02lu:%02lu:%02lu",s/3600,(s%3600)/60,s%60);
  return String(b);
}

void addLog(const String& msg) {
  for(int i=MAX_LOG-1;i>0;i--){ aLog[i]=aLog[i-1]; aTime[i]=aTime[i-1]; }
  aLog[0]=msg; aTime[0]=millis();
  if(aCount<MAX_LOG) aCount++;
  totalA++;
  Serial.println("[LOG] "+msg);
}

bool inWL(const char* m){ String s=String(m); s.toUpperCase();
  for(int i=0;i<wlN;i++) if(wl[i]==s) return true; return false; }
bool inBL(const char* m){ String s=String(m); s.toUpperCase();
  for(int i=0;i<blN;i++) if(bl[i]==s) return true; return false; }

void addWL(String mac){ mac.toUpperCase(); mac.trim(); if(mac.length()!=17) return;
  for(int i=0;i<blN;i++) if(bl[i]==mac){ for(int j=i;j<blN-1;j++) bl[j]=bl[j+1]; blN--; break; }
  for(int i=0;i<wlN;i++) if(wl[i]==mac) return;
  if(wlN<MAX_WL) wl[wlN++]=mac;
  for(int i=0;i<devCount;i++){ devs[i].trusted=inWL(devs[i].mac); devs[i].blocked=inBL(devs[i].mac); }
  eeSave(); }

void remWL(String mac){ mac.toUpperCase();
  for(int i=0;i<wlN;i++) if(wl[i]==mac){ for(int j=i;j<wlN-1;j++) wl[j]=wl[j+1]; wlN--; eeSave(); break; }
  for(int i=0;i<devCount;i++) devs[i].trusted=inWL(devs[i].mac); }

void addBL(String mac){ mac.toUpperCase(); mac.trim(); if(mac.length()!=17) return;
  for(int i=0;i<wlN;i++) if(wl[i]==mac){ for(int j=i;j<wlN-1;j++) wl[j]=wl[j+1]; wlN--; break; }
  for(int i=0;i<blN;i++) if(bl[i]==mac) return;
  if(blN<MAX_BL) bl[blN++]=mac;
  for(int i=0;i<devCount;i++){ devs[i].trusted=inWL(devs[i].mac); devs[i].blocked=inBL(devs[i].mac); }
  addLog("BLOCKED: "+mac); eeSave(); }

void remBL(String mac){ mac.toUpperCase();
  for(int i=0;i<blN;i++) if(bl[i]==mac){ for(int j=i;j<blN-1;j++) bl[j]=bl[j+1]; blN--; eeSave(); break; }
  for(int i=0;i<devCount;i++) devs[i].blocked=inBL(devs[i].mac); }

int findDev(const char* mac){ for(int i=0;i<devCount;i++) if(strcmp(devs[i].mac,mac)==0) return i; return -1; }

void setAlarm(int lv) {
  digitalWrite(LED_SAFE,    lv==0?HIGH:LOW);
  digitalWrite(LED_SUSPECT, lv==1?HIGH:LOW);
  digitalWrite(LED_DANGER,  lv>=2?HIGH:LOW);
  unsigned long now=millis();
  if(lv>=2 && now-tLastBuzz>7000) {
    tLastBuzz=now;
    for(int i=0;i<3;i++){
      digitalWrite(BUZZER,HIGH); delay(150);
      digitalWrite(BUZZER,LOW);  delay(100);
    }
  } else if(lv==1 && now-tLastBuzz>12000) {
    tLastBuzz=now;
    digitalWrite(BUZZER,HIGH); delay(100);
    digitalWrite(BUZZER,LOW);  delay(80);
    digitalWrite(BUZZER,HIGH); delay(100);
    digitalWrite(BUZZER,LOW);
  } else if(lv==0) {
    digitalWrite(BUZZER,LOW);
  }
}

// ================================================================
//                       LAN PROBE LOGIC
// ================================================================
void processDev(const char* mac, const char* ip) {
  if(!mac||!ip) return;
  if(mac[0]=='F'&&mac[1]=='F') return;
  if(strcmp(ip,"0.0.0.0")==0) return;
  if(!staMode) return;
  if(WiFi.localIP().toString()==String(ip)) return;

  String macStr=String(mac); macStr.toUpperCase();
  int idx=findDev(macStr.c_str());

  if(idx==-1) {
    if(devCount>=MAX_DEV) return;
    idx=devCount++;
    strncpy(devs[idx].mac,    macStr.c_str(),17); devs[idx].mac[17]='\0';
    strncpy(devs[idx].ip,     ip,            15); devs[idx].ip[15]='\0';
    strncpy(devs[idx].prevIP, ip,            15); devs[idx].prevIP[15]='\0';
    devs[idx].trusted   = inWL(macStr.c_str());
    devs[idx].blocked   = inBL(macStr.c_str());
    devs[idx].lastSeen  = millis();
    devs[idx].firstSeen = millis();
    devs[idx].blockHits = 0;
    String brand=getBrand(macStr.c_str());
    strncpy(devs[idx].brand,brand.c_str(),23); devs[idx].brand[23]='\0';

    if(devs[idx].blocked) {
      devs[idx].blockHits++;
      addLog("BLOCKED: "+macStr+" @ "+String(ip)+" ["+brand+"]");
      threatLevel=2; threatMAC=macStr; threatIP=String(ip);
      threatInfo=brand+" BLACKLISTED";
      setAlarm(2);
      teleAlert("*BLOCKED DEVICE*\n\nMAC: `"+macStr+"`\nBrand: "+brand+"\nIP: `"+String(ip)+"`\nAttempt: #"+String(devs[idx].blockHits)+"\nTime: "+uptime(), true);
    } else if(!devs[idx].trusted) {
      addLog("INTRUDER: "+macStr+" @ "+String(ip)+" ["+brand+"]");
      threatLevel=2; threatMAC=macStr; threatIP=String(ip);
      threatInfo=brand+" UNKNOWN DEVICE";
      setAlarm(2);
      teleAlert("*INTRUDER ON YOUR NETWORK!*\n\nBrand: *"+brand+"*\nMAC: `"+macStr+"`\nIP: `"+String(ip)+"`\nTime: "+uptime()+"\n\nDashboard: http://"+WiFi.localIP().toString(), true);
    } else {
      Serial.println("[OK] "+macStr+" @ "+String(ip)+" ["+brand+"]");
    }
  } else {
    devs[idx].lastSeen=millis();
    devs[idx].trusted=inWL(macStr.c_str());
    devs[idx].blocked=inBL(macStr.c_str());

    if(devs[idx].trusted &&
       strcmp(devs[idx].ip,ip)!=0 &&
       strlen(devs[idx].ip)>0 &&
       millis()-devs[idx].firstSeen>60000) {
      String oldIP=String(devs[idx].ip);
      addLog("IP CHANGE: "+macStr+" "+oldIP+" -> "+String(ip));
      strncpy(devs[idx].prevIP,devs[idx].ip,15); devs[idx].prevIP[15]='\0';
      if(threatLevel==0){
        threatLevel=1; threatMAC=macStr; threatIP=String(ip);
        threatInfo="IP changed: "+oldIP+" to "+String(ip); setAlarm(1);
        teleAlert("*IP Change*\nMAC: `"+macStr+"`\nWas: `"+oldIP+"` Now: `"+String(ip)+"`", false);
      }
    }
    strncpy(devs[idx].ip,ip,15); devs[idx].ip[15]='\0';

    if(devs[idx].blocked){
      devs[idx].blockHits++;
      addLog("BLOCKED RETURN: "+macStr+" #"+String(devs[idx].blockHits));
      if(threatLevel<2){
        threatLevel=2; threatMAC=macStr; threatIP=String(ip);
        threatInfo=String(devs[idx].brand)+" BLACKLISTED #"+String(devs[idx].blockHits);
        setAlarm(2);
        teleAlert("*Blocked device back!*\n`"+macStr+"`\nAttempt #"+String(devs[idx].blockHits), true);
      }
    } else if(!devs[idx].trusted && threatLevel<2){
      threatLevel=2; threatMAC=macStr; threatIP=String(ip);
      threatInfo=String(devs[idx].brand)+" UNKNOWN";
      setAlarm(2);
    }
  }
}

void readARP() {
  ip4_addr_t *pIP;
  struct netif* pNI;
  struct eth_addr *pEth;
  for(int i=0;i<ARP_TABLE_SIZE;i++){
    if(etharp_get_entry(i,&pIP,&pNI,&pEth)){
      char mac[18],ip[16];
      snprintf(mac,sizeof(mac),"%02X:%02X:%02X:%02X:%02X:%02X",
        pEth->addr[0],pEth->addr[1],pEth->addr[2],
        pEth->addr[3],pEth->addr[4],pEth->addr[5]);
      snprintf(ip,sizeof(ip),"%u.%u.%u.%u",
        ip4_addr1(pIP),ip4_addr2(pIP),ip4_addr3(pIP),ip4_addr4(pIP));
      processDev(mac,ip);
    }
  }
}

void tcpProbe(IPAddress t) {
  WiFiClient c;
  c.setTimeout(PROBE_MS);
  if(c.connect(t,80))  { c.stop(); return; }
  if(c.connect(t,443)) { c.stop(); return; }
  if(c.connect(t,22))  { c.stop(); return; }
  c.connect(t,1); c.stop();
}

// Cooperative service helper - keep web server / DNS responsive
inline void serviceClients() {
  srv.handleClient();
  dnsServer.processNextRequest();
  ESP.wdtFeed();
  yield();
}

void runScan() {
  if(scanning||!staMode) return;
  scanning=true; scanProg=0;

  IPAddress base=WiFi.localIP();
  uint8_t n0=base[0],n1=base[1],n2=base[2],myOct=base[3];
  Serial.printf("[SCAN] %u.%u.%u.1-254\n",n0,n1,n2);

  auto probe=[&](int last){
    serviceClients();
    scanProg=last;
    if((uint8_t)last==myOct) return;
    IPAddress t(n0,n1,n2,(uint8_t)last);
    tcpProbe(t);
    delay(2);
    readARP();
    serviceClients();
  };

  probe(1); readARP();
  for(int i=2;  i<=50;  i++) probe(i);
  for(int i=100;i<=200; i++) probe(i);
  for(int i=51; i<=99;  i++) probe(i);
  for(int i=201;i<=254; i++) probe(i);
  readARP();

  bool red=false,yellow=false;
  for(int i=0;i<devCount;i++){
    if(millis()-devs[i].lastSeen>TIMEOUT_MS) continue;
    if(devs[i].blocked||!devs[i].trusted){ red=true; break; }
    if(strcmp(devs[i].ip,devs[i].prevIP)!=0) yellow=true;
  }
  if(!red&&!yellow){ threatLevel=0; threatMAC=""; threatIP=""; threatInfo=""; setAlarm(0); }
  else if(!red&&yellow&&threatLevel<1){ threatLevel=1; setAlarm(1); }

  scanning=false; scanProg=0;
  Serial.printf("[SCAN] Done. Devices: %d\n",devCount);
}

// ================================================================
//                  WIFI-AP SCAN STATE MACHINE
//   Stays in AP_STA - never calls softAPdisconnect()
// ================================================================
void wifiScanTick() {
  switch(wifiScanState) {
    case WS_REQUESTED: {
      // Make sure we are in dual-mode so AP keeps running
      if(WiFi.getMode()!=WIFI_AP_STA) WiFi.mode(WIFI_AP_STA);
      WiFi.scanDelete();
      // (false=async, false=show_hidden, channel=0=all)
      WiFi.scanNetworks(true, false);
      wifiScanState = WS_RUNNING;
      Serial.println(F("[WiFi] Async scan started in AP_STA"));
      break;
    }
    case WS_RUNNING: {
      int n = WiFi.scanComplete();
      if(n == WIFI_SCAN_RUNNING) return;
      if(n < 0) {
        Serial.printf("[WiFi] Scan failed (%d)\n",n);
        scanCount=0; scanCacheTime=millis();
        wifiScanState = WS_DONE;
        return;
      }
      int cnt = (n>MAX_NETS)?MAX_NETS:n;
      // sort by RSSI (descending)
      int ord[MAX_NETS];
      for(int i=0;i<cnt;i++) ord[i]=i;
      for(int i=0;i<cnt-1;i++)
        for(int j=i+1;j<cnt;j++)
          if(WiFi.RSSI(ord[j])>WiFi.RSSI(ord[i])){ int t=ord[i]; ord[i]=ord[j]; ord[j]=t; }
      scanCount=0;
      for(int k=0;k<cnt;k++){
        int ii=ord[k];
        scanSSIDs[scanCount]=WiFi.SSID(ii);
        scanRSSIs[scanCount]=WiFi.RSSI(ii);
        scanEncs [scanCount]=WiFi.encryptionType(ii);
        scanChans[scanCount]=WiFi.channel(ii);
        scanCount++;
      }
      WiFi.scanDelete();
      scanCacheTime=millis();
      Serial.printf("[WiFi] %d networks cached\n",scanCount);
      wifiScanState = WS_DONE;
      break;
    }
    default: break;
  }
}

// ================================================================
//                          UI / CSS
// ================================================================
String getCSS(const String& col, const String& bg) {
  String c="";
  c+="*{margin:0;padding:0;box-sizing:border-box}";
  c+="body{background:"+bg+";color:#ccc;font-family:'Courier New',monospace;font-size:13px}";
  c+="a{text-decoration:none;color:inherit}";
  c+=".hdr{background:#070707;padding:15px;text-align:center;border-bottom:2px solid "+col+"}";
  c+=".hdr h1{font-size:20px;color:"+col+";letter-spacing:5px}";
  c+=".sub{color:#2a2a2a;font-size:9px;margin-top:4px;letter-spacing:3px}";
  c+=".pill{display:inline-block;background:#080f18;color:#3399cc;border:1px solid #1a3a55;padding:3px 10px;border-radius:10px;font-size:10px;margin-top:7px}";
  c+=".live{display:inline-block;width:6px;height:6px;border-radius:50%;background:#00ff88;margin-right:4px;animation:bk 1.4s infinite}";
  c+="@keyframes bk{0%,100%{opacity:1}50%{opacity:.1}}";
  c+=".nav{display:flex;background:#080808;border-bottom:1px solid #141414}";
  c+=".nav a{flex:1;padding:9px 4px;text-align:center;font-size:10px;color:#444;border-right:1px solid #141414;letter-spacing:1px}";
  c+=".nav a:last-child{border:none}";
  c+=".nav a.on,.nav a:hover{color:"+col+";background:#0d0d0d}";
  c+=".status{margin:12px;padding:18px;border:2px solid "+col+";border-radius:9px;text-align:center}";
  c+=".sl{color:"+col+";opacity:.4;font-size:10px;letter-spacing:5px}";
  c+=".sm{font-size:24px;font-weight:bold;color:"+col+";margin:6px 0}";
  c+=".sd{color:#444;font-size:11px;line-height:1.8}";
  c+=".si{color:#ff7777;font-size:12px;margin-top:5px;font-weight:bold}";
  c+=".sr{color:#ffaa44;font-size:10px;margin-top:3px}";
  c+=".prog{background:#111;border-radius:3px;height:4px;margin-top:9px;overflow:hidden}";
  c+=".progb{height:4px;border-radius:3px;background:#4488cc}";
  c+=".cards{display:flex;gap:6px;margin:0 12px 12px;flex-wrap:wrap}";
  c+=".card{flex:1;min-width:55px;background:#0d0d0d;border:1px solid #181818;border-radius:7px;padding:10px 8px;text-align:center}";
  c+=".cl{color:#333;font-size:8px;text-transform:uppercase;letter-spacing:2px;margin-bottom:6px}";
  c+=".cv{font-size:17px;font-weight:bold;color:"+col+"}";
  c+=".cv.r{color:#ff3333}.cv.y{color:#ffaa00}";
  c+=".box{margin:0 12px 12px;background:#090909;border:1px solid #161616;border-radius:8px;padding:12px}";
  c+=".bh{color:#2a2a2a;font-size:9px;text-transform:uppercase;letter-spacing:3px;padding-bottom:9px;border-bottom:1px solid #141414;margin-bottom:10px}";
  c+=".dev{display:flex;align-items:center;padding:8px 0;border-bottom:1px solid #111;gap:7px;flex-wrap:wrap}";
  c+=".dev:last-child{border-bottom:none}";
  c+=".dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}";
  c+=".dg{background:#00cc55}.dy{background:#ffaa00}.dr{background:#ff3333}.dk{background:#8800cc}";
  c+=".di{flex:1;min-width:100px}";
  c+=".dm{color:#bbb;font-size:12px;font-weight:bold}";
  c+=".dd{color:#333;font-size:10px;margin-top:3px;line-height:1.7}";
  c+=".dv{color:#3399cc;font-size:10px}";
  c+=".dbl{color:#8800cc;font-size:9px}";
  c+=".btns{display:flex;gap:4px;flex-wrap:wrap}";
  c+=".btn{padding:4px 9px;border-radius:4px;font-size:9px;cursor:pointer;font-family:monospace;display:inline-block;white-space:nowrap;border:1px solid}";
  c+=".bt{background:#002018;color:#00cc55;border-color:#005533}";
  c+=".br{background:#1a0000;color:#cc4444;border-color:#660000}";
  c+=".by{background:#0f0800;color:#cc8800;border-color:#553300}";
  c+=".scanb{display:block;margin:0 12px 12px;background:#080e18;color:#4488cc;border:1px solid #1a3a55;padding:9px;border-radius:6px;text-align:center;font-family:monospace;font-size:12px;letter-spacing:1px}";
  c+="input{background:#060606;color:#bbb;border:1px solid #1f1f1f;padding:9px;border-radius:5px;width:100%;margin-top:8px;font-family:monospace;font-size:12px}";
  c+=".subm{background:#001a08;color:#00cc55;border:1px solid #004422;padding:10px;border-radius:5px;width:100%;margin-top:9px;font-family:monospace;font-size:12px;cursor:pointer}";
  c+=".subm.red{background:#1a0000;color:#cc4444;border-color:#660000}";
  c+=".wrow{display:flex;align-items:center;padding:9px 6px;border-bottom:1px solid #111;cursor:pointer;gap:8px}";
  c+=".wrow:hover{background:#0d0d0d}.wrow:last-child{border-bottom:none}";
  c+=".wssid{flex:1;color:#bbb;font-size:12px}";
  c+=".wrssi{color:#2a2a2a;font-size:10px;width:60px;text-align:right}";
  c+=".wsel{color:#00cc55;font-size:10px;padding:3px 7px;border:1px solid #005533;border-radius:4px;background:#001a08}";
  c+=".alrt{padding:7px 0;border-bottom:1px solid #111;font-size:11px;line-height:1.5}";
  c+=".alrt:last-child{border-bottom:none}";
  c+=".ar{color:#cc3333}.ay{color:#cc8800}";
  c+=".at{color:#252525;font-size:10px;margin-right:6px}";
  c+=".ftr{text-align:center;color:#1a1a1a;font-size:10px;padding:14px;line-height:1.9}";
  return c;
}

String hdrNav(const String& col, const String& pg) {
  String h="";
  h+="<div class='hdr'><h1>IoT Sentinel</h1>";
  h+="<div class='sub'>NETWORK GUARDIAN -- ALWAYS WATCHING</div>";
  if(staMode){
    h+="<div class='pill'><span class='live'></span>";
    h+=WiFi.localIP().toString()+" | "+WiFi.SSID();
    h+=" | "+String(WiFi.RSSI())+"dBm | Up:"+uptime();
    h+="</div>";
  } else {
    h+="<div class='pill' style='color:#ffaa00'>AP Mode: IoT-Sentinel -- ";
    h+="<a href='/wifi' style='color:#4488cc'>Setup WiFi</a></div>";
  }
  h+="</div>";
  h+="<div class='nav'>";
  String c1=(pg=="/")?String("on"):String("");
  String c2=(pg=="/devices")?String("on"):String("");
  String c3=(pg=="/wifi")?String("on"):String("");
  String c4=(pg=="/log")?String("on"):String("");
  h+="<a href='/' class='"+c1+"'>Monitor</a>";
  h+="<a href='/devices' class='"+c2+"'>Devices</a>";
  h+="<a href='/wifi' class='"+c3+"'>WiFi</a>";
  h+="<a href='/log' class='"+c4+"'>Log</a>";
  h+="</div>";
  return h;
}

// ================================================================
//                          PAGE: /
// ================================================================
void handleRoot() {
  String col=threatLevel==0?String("#00ff88"):threatLevel==1?String("#ffaa00"):String("#ff3333");
  String bg =threatLevel==0?String("#060e1a"):threatLevel==1?String("#110d00"):String("#110000");

  String p="";
  p+="<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  p+="<meta name='viewport' content='width=device-width,initial-scale=1'>";
  if(!scanning) p+="<meta http-equiv='refresh' content='8'>";
  p+="<title>IoT Sentinel</title><style>"+getCSS(col,bg)+"</style></head><body>";
  p+=hdrNav(col,"/");

  String st=threatLevel==0?String("SECURE"):threatLevel==1?String("SUSPICIOUS"):String("THREAT DETECTED");
  String sl=threatLevel==0?String("ALL CLEAR"):threatLevel==1?String("WARNING"):String("ALERT");

  p+="<div class='status'><div class='sl'>"+sl+"</div><div class='sm'>"+st+"</div>";
  if(threatLevel>0&&threatMAC.length()>0){
    p+="<div class='si'>"+threatMAC+"</div>";
    p+="<div class='sr'>"+threatInfo+"</div>";
    p+="<div class='sd'>IP: "+threatIP+"</div>";
  }
  if(scanning){
    p+="<div class='sd' style='color:#3399cc'>Scanning "+String(scanProg)+"/254...</div>";
    p+="<div class='prog'><div class='progb' style='width:"+String(scanProg*100/254)+"%'></div></div>";
  } else if(staMode){
    long nxt=((long)SCAN_MS-(long)(millis()-tLastScan))/1000;
    if(nxt<0) nxt=0;
    p+="<div class='sd'>Next scan in "+String(nxt)+"s</div>";
  }
  p+="</div>";

  int ac=0,tc=0,uc=0,bc=0;
  for(int i=0;i<devCount;i++){
    if(millis()-devs[i].lastSeen>TIMEOUT_MS) continue;
    ac++;
    if(devs[i].blocked) bc++;
    else if(!devs[i].trusted) uc++;
    else tc++;
  }

  p+="<div class='cards'>";
  p+="<div class='card'><div class='cl'>Online</div><div class='cv'>"+String(ac)+"</div></div>";
  p+="<div class='card'><div class='cl'>Trusted</div><div class='cv'>"+String(tc)+"</div></div>";
  p+="<div class='card'><div class='cl'>Unknown</div><div class='cv"+(uc>0?String(" r"):String(""))+"'>"+String(uc)+"</div></div>";
  p+="<div class='card'><div class='cl'>Blocked</div><div class='cv"+(bc>0?String(" r"):String(""))+"'>"+String(bc)+"</div></div>";
  p+="<div class='card'><div class='cl'>Alerts</div><div class='cv'>"+String(totalA)+"</div></div>";
  p+="</div>";

  p+="<a class='scanb' href='"+(staMode?String("/scan"):String("/wifi"))+"'>";
  if(scanning)      p+="Scanning...";
  else if(staMode)  p+="Scan Network Now";
  else              p+="Configure WiFi First";
  p+="</a>";

  p+="<div class='box'><div class='bh'>Connected Devices</div>";
  int shown=0;
  for(int i=0;i<devCount&&shown<10;i++){
    if(millis()-devs[i].lastSeen>TIMEOUT_MS) continue;
    shown++;
    String dot=devs[i].blocked?String("dk"):(!devs[i].trusted?String("dr"):String("dg"));
    String brand=String(devs[i].brand);
    p+="<div class='dev'><div class='dot "+dot+"'></div><div class='di'>";
    p+="<div class='dm'>"+String(devs[i].mac)+"</div>";
    p+="<div class='dd'><span class='dv'>"+brandIcon(brand)+" "+brand+"</span> | "+String(devs[i].ip);
    if(devs[i].blocked) p+=" | <span class='dbl'>BLOCKED ("+String(devs[i].blockHits)+"x)</span>";
    p+="</div></div><div class='btns'>";
    if(devs[i].blocked){
      p+="<a class='btn bt' href='/trust?mac="+String(devs[i].mac)+"'>Unblock</a>";
    } else if(!devs[i].trusted){
      p+="<a class='btn bt' href='/trust?mac="+String(devs[i].mac)+"'>Trust</a>";
      p+="<a class='btn br' href='/block?mac="+String(devs[i].mac)+"'>Block</a>";
    } else {
      p+="<a class='btn by' href='/remove?mac="+String(devs[i].mac)+"'>Remove</a>";
      p+="<a class='btn br' href='/block?mac="+String(devs[i].mac)+"'>Block</a>";
    }
    p+="</div></div>";
  }
  if(shown==0) p+="<div style='color:#1e1e1e;font-size:12px;padding:8px 0'>"+(staMode?String("No devices. Click Scan."):String("Connect WiFi first."))+"</div>";
  p+="</div>";

  p+="<div class='box'><div class='bh'>Recent Alerts ("+String(totalA)+")</div>";
  if(aCount==0){
    p+="<div style='color:#1e1e1e;font-size:12px;padding:8px 0'>No alerts. Network clean.</div>";
  } else {
    for(int i=0;i<min(aCount,5);i++){
      String cls=aLog[i].startsWith("IP")?String("ay"):String("ar");
      unsigned long ago=(millis()-aTime[i])/1000;
      char ag[16];
      if(ago<60) sprintf(ag,"%lus",ago);
      else if(ago<3600) sprintf(ag,"%lum",ago/60);
      else sprintf(ag,"%luh",ago/3600);
      p+="<div class='alrt "+cls+"'><span class='at'>["+String(ag)+"]</span>"+aLog[i]+"</div>";
    }
    if(aCount>5) p+="<div style='text-align:right;margin-top:6px'><a href='/log' style='color:#4488cc;font-size:10px'>Full log</a></div>";
  }
  p+="</div>";
  p+="<div class='ftr'>IoT Sentinel v8.5 | EIDIA UEMF 2025<br>Elmaghraoui Mouad &amp; Youssef Boutayeb</div>";
  p+="</body></html>";
  srv.send(200,"text/html; charset=UTF-8",p);
}

// ================================================================
//                       PAGE: /devices
// ================================================================
void handleDevices() {
  String col=threatLevel==0?String("#00ff88"):threatLevel==1?String("#ffaa00"):String("#ff3333");
  String bg=threatLevel==0?String("#060e1a"):threatLevel==1?String("#110d00"):String("#110000");

  String p="";
  p+="<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  p+="<meta name='viewport' content='width=device-width,initial-scale=1'>";
  p+="<title>Devices</title><style>"+getCSS(col,bg)+"</style></head><body>";
  p+=hdrNav(col,"/devices");

  p+="<div class='box'><div class='bh'>Trusted -- Whitelist ("+String(wlN)+")</div>";
  bool any=false;
  for(int i=0;i<devCount;i++){
    if(!devs[i].trusted) continue;
    any=true;
    String brand=String(devs[i].brand);
    unsigned long ago=(millis()-devs[i].lastSeen)/1000;
    char ag[16];
    if(ago<60) sprintf(ag,"%lus",ago);
    else if(ago<3600) sprintf(ag,"%lum",ago/60);
    else sprintf(ag,"%luh",ago/3600);
    p+="<div class='dev'><div class='dot dg'></div><div class='di'>";
    p+="<div class='dm'>"+String(devs[i].mac)+"</div>";
    p+="<div class='dd'><span class='dv'>"+brandIcon(brand)+" "+brand+"</span> | "+String(devs[i].ip)+" | "+String(ag)+" ago</div>";
    p+="</div><div class='btns'>";
    p+="<a class='btn by' href='/remove?mac="+String(devs[i].mac)+"'>Remove</a>";
    p+="<a class='btn br' href='/block?mac="+String(devs[i].mac)+"'>Block</a>";
    p+="</div></div>";
  }
  for(int i=0;i<wlN;i++){
    if(findDev(wl[i].c_str())!=-1) continue;
    p+="<div class='dev'><div class='dot dg' style='opacity:.2'></div><div class='di'>";
    p+="<div class='dm' style='color:#282828'>"+wl[i]+"</div>";
    p+="<div class='dd' style='color:#1e1e1e'>offline</div></div>";
    p+="<div class='btns'><a class='btn by' href='/remove?mac="+wl[i]+"'>Remove</a></div></div>";
  }
  if(!any&&wlN==0) p+="<div style='color:#1e1e1e;font-size:12px;padding:8px 0'>No trusted devices yet.</div>";
  p+="</div>";

  p+="<div class='box'><div class='bh'>Unknown Devices</div>";
  bool anyU=false;
  for(int i=0;i<devCount;i++){
    if(devs[i].trusted||devs[i].blocked) continue;
    if(millis()-devs[i].lastSeen>TIMEOUT_MS) continue;
    anyU=true;
    String brand=String(devs[i].brand);
    p+="<div class='dev'><div class='dot dr'></div><div class='di'>";
    p+="<div class='dm'>"+String(devs[i].mac)+"</div>";
    p+="<div class='dd'><span class='dv'>"+brandIcon(brand)+" "+brand+"</span> | "+String(devs[i].ip)+"</div>";
    p+="</div><div class='btns'>";
    p+="<a class='btn bt' href='/trust?mac="+String(devs[i].mac)+"'>Trust</a>";
    p+="<a class='btn br' href='/block?mac="+String(devs[i].mac)+"'>Block</a>";
    p+="</div></div>";
  }
  if(!anyU) p+="<div style='color:#1e1e1e;font-size:12px;padding:8px 0'>No unknown devices.</div>";
  p+="</div>";

  p+="<div class='box' style='border-color:#1a0000'><div class='bh' style='color:#330000'>Blacklisted ("+String(blN)+")</div>";
  for(int i=0;i<blN;i++){
    int idx=findDev(bl[i].c_str());
    String brand=idx!=-1?String(devs[idx].brand):String("Unknown");
    String ipStr=idx!=-1?String(devs[idx].ip):String("--");
    int hits=idx!=-1?devs[idx].blockHits:0;
    p+="<div class='dev'><div class='dot dk'></div><div class='di'>";
    p+="<div class='dm'>"+bl[i]+"</div>";
    p+="<div class='dd'><span class='dv'>"+brandIcon(brand)+" "+brand+"</span> | "+ipStr;
    if(hits>0) p+=" | <span class='dbl'>"+String(hits)+" attempts</span>";
    p+="</div></div><div class='btns'>";
    p+="<a class='btn bt' href='/trust?mac="+bl[i]+"'>Unblock+Trust</a>";
    p+="<a class='btn by' href='/unblock?mac="+bl[i]+"'>Remove Block</a>";
    p+="</div></div>";
  }
  if(blN==0) p+="<div style='color:#1e1e1e;font-size:12px;padding:8px 0'>Blacklist is empty.</div>";
  p+="</div>";

  p+="<div class='box'><div class='bh'>Manual MAC Entry</div>";
  p+="<form action='/trust' method='GET'><input type='text' name='mac' placeholder='AA:BB:CC:DD:EE:FF'>";
  p+="<button class='subm' type='submit'>Add to Whitelist</button></form>";
  p+="<form action='/block' method='GET' style='margin-top:10px'><input type='text' name='mac' placeholder='AA:BB:CC:DD:EE:FF'>";
  p+="<button class='subm red' type='submit'>Add to Blacklist</button></form></div>";
  p+="<div class='ftr'>IoT Sentinel v8.5 | Elmaghraoui Mouad &amp; Youssef Boutayeb</div>";
  p+="</body></html>";
  srv.send(200,"text/html; charset=UTF-8",p);
}

// ================================================================
//                  PAGE: /wifi  (AP-safe)
// ================================================================
void handleWiFi() {
  // 1) trigger refresh - just flips the state machine, returns immediately
  if (srv.hasArg("refresh")) {
    if (wifiScanState == WS_IDLE || wifiScanState == WS_DONE) {
      wifiScanState = WS_REQUESTED;
    }
    String p="<!DOCTYPE html><html><head><meta charset='UTF-8'>";
    p+="<meta name='viewport' content='width=device-width,initial-scale=1'>";
    p+="<meta http-equiv='refresh' content='4;url=/wifi'>";
    p+="<title>Scanning</title><style>"+getCSS("#4488cc","#060c14")+"</style></head><body>";
    p+=hdrNav("#4488cc","/wifi");
    p+="<div class='box' style='text-align:center;padding:30px'>";
    p+="<div style='color:#4488cc;font-size:14px;margin-bottom:8px'>Scanning nearby networks...</div>";
    p+="<div style='color:#555;font-size:11px'>AP stays online - your phone will not disconnect</div>";
    p+="<div class='prog' style='margin-top:18px'><div class='progb' style='width:50%;animation:bk 1.4s infinite'></div></div>";
    p+="</div></body></html>";
    srv.send(200,"text/html; charset=UTF-8",p);
    return;
  }

  // 2) render
  bool busy = (wifiScanState == WS_REQUESTED || wifiScanState == WS_RUNNING);

  String p="";
  p+="<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  p+="<meta name='viewport' content='width=device-width,initial-scale=1'>";
  if(busy) p+="<meta http-equiv='refresh' content='3;url=/wifi'>";
  p+="<title>WiFi</title><style>"+getCSS("#4488cc","#060c14")+"</style></head><body>";
  p+=hdrNav("#4488cc","/wifi");

  if(staMode){
    p+="<div class='box'><div class='bh'>Connected</div>";
    p+="<div class='dev'><div class='dot dg'></div><div class='di'>";
    p+="<div class='dm'>"+WiFi.SSID()+"</div>";
    p+="<div class='dd'>IP: "+WiFi.localIP().toString();
    p+=" | GW: "+WiFi.gatewayIP().toString();
    p+=" | "+String(WiFi.RSSI())+"dBm</div>";
    p+="</div></div></div>";
  }

  p+="<div class='box'><div class='bh'>Nearby Networks -- Tap to Select</div>";

  if(busy){
    p+="<div style='color:#4488cc;padding:18px;text-align:center;font-size:12px'>";
    p+="Scanning... page will auto-refresh.<br>";
    p+="<span style='color:#555;font-size:10px'>AP remains online during scan.</span></div>";
  } else if(scanCount == 0){
    p+="<div style='color:#777;font-size:12px;padding:15px;text-align:center'>";
    p+="No networks cached.<br>";
    p+="<a href='/wifi?refresh=1' style='color:#4488cc;font-size:13px;text-decoration:underline'>Tap to scan now</a></div>";
  } else {
    for(int k=0;k<scanCount;k++){
      String ss=scanSSIDs[k];
      int rs=scanRSSIs[k];
      bool op=(scanEncs[k]==ENC_TYPE_NONE);
      bool cur=(ss==WiFi.SSID()&&staMode);
      String bars=rs>-50?String("[FULL]"):rs>-62?String("[GOOD]"):rs>-72?String("[FAIR]"):String("[WEAK]");
      String lkColor=op?String("#cc4444"):String("#4488cc");
      String lkText=op?String("[open]"):String("[lock]");
      String prefix=cur?String("[*] "):String("");
      String ssE=ss; ssE.replace("\\","\\\\"); ssE.replace("'","\\'");
      p+="<div class='wrow' onclick=\"document.getElementById('sid').value='"+ssE+"';document.getElementById('pw').focus();\">";
      p+="<span style='color:"+lkColor+";font-size:11px'>"+lkText+"</span>";
      p+="<span class='wssid'>"+prefix+ss+"</span>";
      p+="<span class='wrssi'>"+bars+" "+String(rs)+"</span>";
      p+="<span class='wsel'>Select</span></div>";
    }
    if(scanCacheTime>0){
      unsigned long age=(millis()-scanCacheTime)/1000;
      p+="<div style='color:#333;font-size:10px;padding:6px 0;text-align:center'>cached "+String(age)+"s ago</div>";
    }
  }

  p+="<div style='text-align:center;padding:10px'>";
  p+="<a href='/wifi?refresh=1' style='color:#4488cc;font-size:11px'>";
  p+= (busy?String("Scanning..."):String("Refresh Networks"));
  p+="</a></div></div>";

  p+="<div class='box'><div class='bh'>Connect to Network</div>";
  p+="<form action='/connect' method='GET'>";
  p+="<input id='sid' type='text' name='ssid' placeholder='Network Name (or type hidden SSID)' value='"+String(cfgSSID)+"'>";
  p+="<input id='pw' type='password' name='pass' placeholder='Password (leave empty if open)'>";
  p+="<button class='subm' type='submit'>Connect &amp; Start Guarding</button>";
  p+="</form></div>";
  p+="<div class='ftr'>Settings saved to EEPROM -- survives reboot</div>";
  p+="</body></html>";
  srv.send(200,"text/html; charset=UTF-8",p);
}

// ================================================================
//                          PAGE: /log
// ================================================================
void handleLog() {
  String col=threatLevel==0?String("#00ff88"):threatLevel==1?String("#ffaa00"):String("#ff3333");
  String bg=threatLevel==0?String("#060e1a"):threatLevel==1?String("#110d00"):String("#110000");

  String p="";
  p+="<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  p+="<meta name='viewport' content='width=device-width,initial-scale=1'>";
  p+="<meta http-equiv='refresh' content='15'>";
  p+="<title>Alert Log</title><style>"+getCSS(col,bg)+"</style></head><body>";
  p+=hdrNav(col,"/log");

  p+="<div class='box'><div class='bh'>Alert Log ("+String(totalA)+" total)</div>";
  if(aCount==0){
    p+="<div style='color:#1e1e1e;font-size:12px;padding:10px 0'>No alerts. Network clean.</div>";
  } else {
    for(int i=0;i<aCount;i++){
      String cls=aLog[i].startsWith("IP")?String("ay"):String("ar");
      unsigned long ago=(millis()-aTime[i])/1000;
      char ag[16];
      if(ago<60) sprintf(ag,"%lus ago",ago);
      else if(ago<3600) sprintf(ag,"%lum ago",ago/60);
      else sprintf(ag,"%luh ago",ago/3600);
      p+="<div class='alrt "+cls+"'><span class='at'>["+String(ag)+"]</span>"+aLog[i]+"</div>";
    }
  }
  p+="</div>";
  p+="<div class='ftr'>Auto-refresh 15s | IoT Sentinel v8.5</div>";
  p+="</body></html>";
  srv.send(200,"text/html; charset=UTF-8",p);
}

// ================================================================
//                          SETUP
// ================================================================
void setup() {
  Serial.begin(115200);
  delay(600);
  t0=millis();

  pinMode(LED_SAFE,   OUTPUT); digitalWrite(LED_SAFE,   LOW);
  pinMode(LED_SUSPECT,OUTPUT); digitalWrite(LED_SUSPECT,LOW);
  pinMode(LED_DANGER, OUTPUT); digitalWrite(LED_DANGER, LOW);
  pinMode(BUZZER,     OUTPUT); digitalWrite(BUZZER,     LOW);

  Serial.println(F("\n+==============================+"));
  Serial.println(F(  "|  IoT Sentinel v8.5           |"));
  Serial.println(F(  "|  Stable AP + Captive Portal  |"));
  Serial.println(F(  "|  Mouad & Youssef | EIDIA 2025|"));
  Serial.println(F(  "+==============================+"));

  for(int r=0;r<3;r++){
    digitalWrite(LED_SAFE,   HIGH); delay(80);
    digitalWrite(LED_SUSPECT,HIGH); delay(80);
    digitalWrite(LED_DANGER, HIGH); delay(80);
    digitalWrite(BUZZER,HIGH); delay(40);
    digitalWrite(BUZZER,LOW);  delay(40);
    digitalWrite(LED_SAFE,   LOW);
    digitalWrite(LED_SUSPECT,LOW);
    digitalWrite(LED_DANGER, LOW);
    delay(60);
  }

  eeLoad();

  bool connected=false;
  if(strlen(cfgSSID)>0){
    Serial.println("[WiFi] Connecting: "+String(cfgSSID));
    WiFi.mode(WIFI_STA);
    WiFi.setSleepMode(WIFI_NONE_SLEEP);
    WiFi.persistent(false);
    WiFi.setAutoReconnect(true);
    WiFi.begin(cfgSSID,cfgPASS);
    int tries=0;
    while(WiFi.status()!=WL_CONNECTED&&tries<30){
      delay(500); Serial.print(".");
      tries++; digitalWrite(LED_SUSPECT,tries%2);
    }
    digitalWrite(LED_SUSPECT,LOW);
    if(WiFi.status()==WL_CONNECTED){
      connected=true; staMode=true;
      Serial.println();
      Serial.println("[WiFi] Connected!");
      Serial.println("  IP:   "+WiFi.localIP().toString());
      Serial.println("  Open: http://"+WiFi.localIP().toString());
    }
  }

  if(!connected){
    Serial.println(F("[AP] Starting AP_STA mode..."));
    WiFi.persistent(false);
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP(AP_SSID,AP_PASS);
    Serial.println(F("[AP] SSID: IoT-Sentinel"));
    Serial.println(F("[AP] Pass: sentinel2025"));
    Serial.println(F("[AP] URL : http://192.168.4.1"));
    staMode=false;
    digitalWrite(LED_SUSPECT,HIGH);

    // ----- Captive-portal DNS: catches every domain -----
    dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
    dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
    Serial.println(F("[DNS] Captive-portal DNS active"));
  }

  if(staMode){
    teleClient.setInsecure();
    String myMAC=WiFi.macAddress(); myMAC.toUpperCase();
    addWL(myMAC);
    Serial.println("[WL] Auto-trusted self: "+myMAC);

    String bm="*IoT Sentinel Online*\n\n";
    bm+="Network: `"+WiFi.SSID()+"`\n";
    bm+="IP: `"+WiFi.localIP().toString()+"`\n";
    bm+="Dashboard: http://"+WiFi.localIP().toString()+"\n";
    bm+="Trusted: "+String(wlN)+" | Blocked: "+String(blN)+"\n";
    bm+="Watching your network 24/7";
    teleAlert(bm,true);
  }

  // We need Referer for sticky redirects after Trust/Block
  const char* HDRS[] = { "Referer" };
  srv.collectHeaders(HDRS, sizeof(HDRS)/sizeof(HDRS[0]));

  // ---------------- CORE ROUTES ----------------
  srv.on("/",        HTTP_GET, handleRoot);
  srv.on("/devices", HTTP_GET, handleDevices);
  srv.on("/wifi",    HTTP_GET, handleWiFi);
  srv.on("/log",     HTTP_GET, handleLog);

  srv.on("/api", HTTP_GET, [](){
    int ac=0,tc=0,uc=0,bc=0;
    for(int i=0;i<devCount;i++){
      if(millis()-devs[i].lastSeen>TIMEOUT_MS) continue;
      ac++;
      if(devs[i].blocked) bc++;
      else if(!devs[i].trusted) uc++;
      else tc++;
    }
    String j="{\"threat\":"+String(threatLevel);
    j+=",\"mac\":\""+threatMAC+"\"";
    j+=",\"ip\":\""+threatIP+"\"";
    j+=",\"info\":\""+threatInfo+"\"";
    j+=",\"devices\":"+String(ac);
    j+=",\"trusted\":"+String(tc);
    j+=",\"unknown\":"+String(uc);
    j+=",\"blocked\":"+String(bc);
    j+=",\"alerts\":"+String(totalA);
    j+=",\"scanning\":"+String(scanning?"true":"false");
    j+=",\"uptime\":\""+uptime()+"\"}";
    srv.send(200,"application/json",j);
  });

  srv.on("/scan", HTTP_GET, [](){
    srv.sendHeader("Location","/"); srv.send(302,"","");
    delay(50); tLastScan=millis(); runScan();
  });

  srv.on("/trust", HTTP_GET, [](){
    if(srv.hasArg("mac")){
      String mac=srv.arg("mac"); addWL(mac);
      if(threatMAC.equalsIgnoreCase(mac)){
        threatLevel=0; threatMAC=""; threatIP=""; threatInfo=""; setAlarm(0);
      }
    }
    String ref=srv.header("Referer");
    String dest = (ref.indexOf("devices")>=0) ? "/devices" : "/";
    srv.sendHeader("Location",dest); srv.send(302,"","");
  });

  srv.on("/block", HTTP_GET, [](){
    if(srv.hasArg("mac")){
      String mac=srv.arg("mac"); addBL(mac);
      threatLevel=2; threatMAC=mac;
      threatInfo="Manually blocked"; setAlarm(2);
    }
    srv.sendHeader("Location","/devices"); srv.send(302,"","");
  });

  srv.on("/unblock", HTTP_GET, [](){
    if(srv.hasArg("mac")) remBL(srv.arg("mac"));
    srv.sendHeader("Location","/devices"); srv.send(302,"","");
  });

  srv.on("/remove", HTTP_GET, [](){
    if(srv.hasArg("mac")) remWL(srv.arg("mac"));
    srv.sendHeader("Location","/devices"); srv.send(302,"","");
  });

  srv.on("/connect", HTTP_GET, [](){
    if(!srv.hasArg("ssid")){
      srv.sendHeader("Location","/wifi"); srv.send(302,"",""); return;
    }
    String ssid=srv.arg("ssid"); ssid.trim();
    String pass=srv.arg("pass"); pass.trim();
    if(ssid.length()==0){
      srv.sendHeader("Location","/wifi"); srv.send(302,"",""); return;
    }
    srv.send(200,"text/html; charset=UTF-8",
      "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
      "<style>body{background:#060e1a;color:#00ff88;font-family:monospace;"
      "text-align:center;padding-top:80px}</style></head>"
      "<body><h2>Connecting to</h2>"
      "<h2 style='color:#4488cc;margin-top:10px'>"+ssid+"</h2>"
      "<p style='color:#444;margin-top:20px;font-size:12px;line-height:2'>"
      "Saving to EEPROM...<br>Restarting...<br><br>"
      "Check Serial Monitor for IP.</p></body></html>");
    delay(500);
    strncpy(cfgSSID,ssid.c_str(),63); cfgSSID[63]='\0';
    strncpy(cfgPASS,pass.c_str(),63); cfgPASS[63]='\0';
    eeSave(); delay(800); ESP.restart();
  });

  // ---------------- CAPTIVE PORTAL ENDPOINTS ----------------
  // Android (most common) - must reply 204 with empty body
  srv.on("/generate_204",        HTTP_GET, [](){ srv.sendHeader("Location","/"); srv.send(302,"",""); });
  srv.on("/gen_204",             HTTP_GET, [](){ srv.sendHeader("Location","/"); srv.send(302,"",""); });
  // Apple iOS / macOS
  srv.on("/hotspot-detect.html", HTTP_GET, [](){ srv.send(200,"text/html","<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"); });
  srv.on("/library/test/success.html",HTTP_GET, [](){ srv.send(200,"text/html","<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"); });
  // Windows / Microsoft NCSI
  srv.on("/connecttest.txt",     HTTP_GET, [](){ srv.send(200,"text/plain","Microsoft Connect Test"); });
  srv.on("/ncsi.txt",            HTTP_GET, [](){ srv.send(200,"text/plain","Microsoft NCSI"); });
  // Samsung / Xiaomi / Firefox
  srv.on("/canonical.html",      HTTP_GET, [](){ srv.sendHeader("Location","/"); srv.send(302,"",""); });
  srv.on("/success.txt",         HTTP_GET, [](){ srv.send(200,"text/plain","success"); });
  // Anything else - in AP mode redirect to dashboard, in STA mode go to /
  srv.onNotFound([](){
    if(!staMode){
      srv.sendHeader("Location",String("http://")+WiFi.softAPIP().toString()+"/");
      srv.send(302,"","");
    } else {
      srv.sendHeader("Location","/");
      srv.send(302,"","");
    }
  });

  srv.begin();
  Serial.println(F("[WEB] Server ready on port 80"));

  if(staMode){
    digitalWrite(LED_SAFE,HIGH);
    Serial.println(F("[SCAN] First sweep..."));
    runScan(); tLastScan=millis();
  }
}

// ================================================================
//                           LOOP
// ================================================================
void loop() {
  srv.handleClient();
  if(!staMode) dnsServer.processNextRequest();   // captive portal DNS
  wifiScanTick();                                // async wifi scan FSM

  if(staMode && WiFi.status()!=WL_CONNECTED){
    Serial.println(F("[WiFi] Lost - reconnecting..."));
    digitalWrite(LED_SAFE,LOW); digitalWrite(LED_SUSPECT,HIGH);
    WiFi.reconnect();
    int t=0;
    while(WiFi.status()!=WL_CONNECTED && t<20){ delay(500); t++; }
    if(WiFi.status()==WL_CONNECTED){
      Serial.println("[WiFi] Reconnected: "+WiFi.localIP().toString());
      digitalWrite(LED_SUSPECT,LOW); setAlarm(threatLevel);
    }
  }

  if(staMode && !scanning && millis()-tLastScan>=SCAN_MS){
    tLastScan=millis(); runScan();
  }

  static unsigned long lastARP=0;
  if(staMode && !scanning && millis()-lastARP>=8000){
    lastARP=millis(); readARP();
    bool red=false,yellow=false;
    for(int i=0;i<devCount;i++){
      if(millis()-devs[i].lastSeen>TIMEOUT_MS) continue;
      if(devs[i].blocked||!devs[i].trusted){ red=true; break; }
      if(strcmp(devs[i].ip,devs[i].prevIP)!=0) yellow=true;
    }
    if(!red&&!yellow&&threatLevel>0){
      threatLevel=0; threatMAC=""; threatIP=""; threatInfo=""; setAlarm(0);
    } else if(!red&&yellow&&threatLevel==0){
      threatLevel=1; setAlarm(1);
    }
  }

  if(threatLevel>=2 && millis()-tLastBuzz>30000) setAlarm(2);

  delay(2);
}
