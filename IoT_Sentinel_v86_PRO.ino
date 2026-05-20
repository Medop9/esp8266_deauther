/*
 * ============================================================
 *  IoT Sentinel v8.6 PRO — Configurable + Manual Deauth
 *  Network Intrusion Detection System  (24/7 Automatic)
 *  Elmaghraoui Mouad & Youssef Boutayeb | EIDIA UEMF 2025
 * ------------------------------------------------------------
 *  v8.6 NEW vs v8.5:
 *   1. Web-configurable Telegram credentials (token + chatID)
 *   2. /notifications page with setup wizard + test button
 *   3. /settings page (auto-blacklist, scan interval, deauth toggle)
 *   4. Rich intruder alerts with security recommendations
 *   5. Auto-blacklist intruders (optional, off by default)
 *   6. Manual "Kick Device" button - 60s aggressive deauth (Mode 3)
 *      with explicit legal disclaimer and confirmation
 *   7. Works on any WiFi (router OR phone hotspot)
 *   8. Hardcoded token used only as first-boot default
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
  #include "user_interface.h"
}

// ============================================================
//                    DEFAULT CREDENTIALS
//   Used only on first boot (then user can override via web UI)
// ============================================================
#define DEFAULT_BOT_TOKEN "8842467527:AAHsyhwB0rqSTCT7ytLT9xPAhvSCeITOLD0"
#define DEFAULT_CHAT_ID   "5401312485"

const char* AP_SSID = "IoT-Sentinel";
const char* AP_PASS = "sentinel2025";

// --- pinout -----------------------------------------------------------------
#define LED_SAFE    14   // D5
#define LED_SUSPECT 12   // D6
#define LED_DANGER  13   // D7
#define BUZZER      15   // D8

// --- limits -----------------------------------------------------------------
#define MAX_DEV    30
#define MAX_WL     25
#define MAX_BL     25
#define MAX_LOG    20
#define MAX_NETS   20
#define TIMEOUT_MS 600000UL
#define PROBE_MS   300
#define TELE_LIMIT 20000UL
#define DNS_PORT   53

// --- runtime-configurable settings (loaded from EEPROM) ---------------------
char botToken[80] = "";
char chatId[24]   = "";
uint32_t scanIntervalMs = 90000UL;   // 60s, 90s, or 300s
bool autoBlacklist     = false;       // auto-add intruders to BL
bool notifyIPChange    = true;
bool deauthEnabled     = false;       // master switch for kick feature

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
uint8_t       scanBSSIDs[MAX_NETS][6];
int           scanCount = 0;
unsigned long scanCacheTime = 0;

// --- Deauth attack state ----------------------------------------------------
bool          deauthActive    = false;
String        deauthTargetMAC = "";
unsigned long deauthStartMs   = 0;
unsigned long deauthLastBurst = 0;
const unsigned long DEAUTH_DURATION_MS = 60000UL;  // 60 sec
const unsigned long DEAUTH_BURST_GAP   = 3000UL;   // 3 sec between bursts

// --- web stack --------------------------------------------------------------
ESP8266WebServer     srv(80);
DNSServer            dnsServer;
WiFiClientSecure     teleClient;
UniversalTelegramBot bot(DEFAULT_BOT_TOKEN, teleClient);  // re-init in setup

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
//                          EEPROM v8.6
//   Layout:
//   [0]        magic byte (0xA9 = v8.5, 0xB0 = v8.6 with config)
//   [1-64]     SSID
//   [65-128]   PASS
//   [130]      WL count
//   [131-555]  WL entries
//   [556]      BL count
//   [557-981]  BL entries
//   [982-1061] bot token (80 bytes)
//   [1062-1085] chat ID (24 bytes)
//   [1086]     scanIntervalCode (0=60s,1=90s,2=300s)
//   [1087]     autoBlacklist
//   [1088]     notifyIPChange
//   [1089]     deauthEnabled
// ================================================================
#define EE_MAGIC_V85  0xA9
#define EE_MAGIC_V86  0xB0
#define EE_SIZE       1100

void eeSave() {
  EEPROM.begin(EE_SIZE);
  EEPROM.write(0, EE_MAGIC_V86);
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
  // v8.6 config
  for(int i=0;i<80;i++) EEPROM.write(982+i, botToken[i]);
  for(int i=0;i<24;i++) EEPROM.write(1062+i, chatId[i]);
  uint8_t sic = (scanIntervalMs<=60000UL)?0:(scanIntervalMs>=300000UL)?2:1;
  EEPROM.write(1086, sic);
  EEPROM.write(1087, autoBlacklist?1:0);
  EEPROM.write(1088, notifyIPChange?1:0);
  EEPROM.write(1089, deauthEnabled?1:0);
  EEPROM.commit();
  EEPROM.end();
}

void eeLoad() {
  EEPROM.begin(EE_SIZE);
  uint8_t magic = EEPROM.read(0);
  if(magic != EE_MAGIC_V85 && magic != EE_MAGIC_V86){
    EEPROM.end();
    Serial.println(F("[EE] Fresh start - using defaults"));
    strncpy(botToken, DEFAULT_BOT_TOKEN, 79);
    strncpy(chatId,   DEFAULT_CHAT_ID,   23);
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

  if(magic == EE_MAGIC_V86) {
    // load v8.6 config
    for(int i=0;i<80;i++) botToken[i]=EEPROM.read(982+i); botToken[79]='\0';
    for(int i=0;i<24;i++) chatId[i] =EEPROM.read(1062+i); chatId[23]='\0';
    uint8_t sic = EEPROM.read(1086);
    scanIntervalMs = (sic==0)?60000UL:(sic==2)?300000UL:90000UL;
    autoBlacklist  = EEPROM.read(1087)!=0;
    notifyIPChange = EEPROM.read(1088)!=0;
    deauthEnabled  = EEPROM.read(1089)!=0;
  } else {
    // migrating from v8.5 - inject defaults
    Serial.println(F("[EE] Migrating from v8.5 -> v8.6"));
    strncpy(botToken, DEFAULT_BOT_TOKEN, 79);
    strncpy(chatId,   DEFAULT_CHAT_ID,   23);
  }
  // fallback if blank
  if(strlen(botToken)<10) strncpy(botToken, DEFAULT_BOT_TOKEN, 79);
  if(strlen(chatId)<3)    strncpy(chatId,   DEFAULT_CHAT_ID,   23);

  EEPROM.end();
  Serial.printf("[EE] Loaded SSID=%s WL=%d BL=%d AutoBL=%d Deauth=%d\n",
    cfgSSID, wlN, blN, autoBlacklist?1:0, deauthEnabled?1:0);
}

// ================================================================
//                     TELEGRAM HELPER
// ================================================================
void teleAlert(const String& msg, bool force=false) {
  if(!staMode) return;
  if(strlen(botToken)<10 || strlen(chatId)<3) return;
  if(!force && millis()-tLastTele < TELE_LIMIT) return;
  tLastTele = millis();
  Serial.println(F("[TELE] Sending..."));
  bot.updateToken(String(botToken));
  bool ok = bot.sendMessage(chatId, msg, "Markdown");
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
//                    DEAUTH ATTACK ENGINE (Mode 3)
//
//  WARNING: 802.11 deauth frames may be illegal in your country.
//  This feature is disabled by default and requires explicit
//  user opt-in via the /settings page + per-action confirmation.
// ================================================================
uint8_t deauthFrame[26] = {
  0xC0, 0x00,                         // type=mgmt, subtype=deauth
  0x00, 0x00,                         // duration
  0,0,0,0,0,0,                        // dst (target client)   [4..9]
  0,0,0,0,0,0,                        // src (the AP/router)   [10..15]
  0,0,0,0,0,0,                        // bssid (the AP)        [16..21]
  0x00, 0x00,                         // sequence
  0x07, 0x00                          // reason 7 = class 3 frame from non-assoc
};

bool macStringToBytes(const String& mac, uint8_t out[6]) {
  if(mac.length() < 17) return false;
  for(int i=0;i<6;i++){
    char c1=mac[i*3], c2=mac[i*3+1];
    auto hex=[&](char c){return c<='9'?c-'0':(c<='F'?c-'A'+10:c-'a'+10);};
    out[i]=(hex(c1)<<4)|hex(c2);
  }
  return true;
}

void sendDeauthBurst(const uint8_t target[6], const uint8_t apBSSID[6], uint8_t channel) {
  // Set channel via promiscuous mode briefly
  wifi_promiscuous_enable(1);
  wifi_set_channel(channel);

  // build frame: addr1=target, addr2=ap, addr3=ap
  memcpy(deauthFrame+4,  target, 6);
  memcpy(deauthFrame+10, apBSSID, 6);
  memcpy(deauthFrame+16, apBSSID, 6);

  // Send 10 frames per burst (~100ms total)
  for(int i=0;i<10;i++){
    wifi_send_pkt_freedom(deauthFrame, sizeof(deauthFrame), 0);
    delay(2);
    // Also send "from target to AP" for bidirectional kick
    memcpy(deauthFrame+4,  apBSSID, 6);
    memcpy(deauthFrame+10, target,  6);
    wifi_send_pkt_freedom(deauthFrame, sizeof(deauthFrame), 0);
    delay(2);
    memcpy(deauthFrame+4,  target, 6);
    memcpy(deauthFrame+10, apBSSID, 6);
  }
  wifi_promiscuous_enable(0);
}

void startDeauth(const String& targetMAC) {
  if(!deauthEnabled) {
    addLog("DEAUTH BLOCKED: feature disabled in settings");
    return;
  }
  if(deauthActive) {
    addLog("DEAUTH already running");
    return;
  }
  deauthActive    = true;
  deauthTargetMAC = targetMAC;
  deauthTargetMAC.toUpperCase();
  deauthStartMs   = millis();
  deauthLastBurst = 0;
  addLog("DEAUTH START: " + deauthTargetMAC);

  String msg = "*Manual Kick Triggered*\n\n";
  msg += "Target: `" + deauthTargetMAC + "`\n";
  msg += "Duration: 60 seconds\n";
  msg += "Mode: Aggressive (Mode 3)\n";
  msg += "Time: " + uptime();
  teleAlert(msg, true);
}

void stopDeauth(const String& reason) {
  if(!deauthActive) return;
  deauthActive = false;
  addLog("DEAUTH STOP: " + reason);
  String msg = "*Kick Finished*\n\n";
  msg += "Target: `" + deauthTargetMAC + "`\n";
  msg += "Reason: " + reason;
  teleAlert(msg, true);
  deauthTargetMAC = "";
}

void deauthTick() {
  if(!deauthActive) return;
  unsigned long now = millis();
  if(now - deauthStartMs > DEAUTH_DURATION_MS) {
    stopDeauth("60s timeout reached");
    return;
  }
  if(now - deauthLastBurst < DEAUTH_BURST_GAP) return;
  deauthLastBurst = now;

  // We need: target MAC bytes, AP BSSID, AP channel
  uint8_t targetBytes[6];
  if(!macStringToBytes(deauthTargetMAC, targetBytes)) return;

  uint8_t apBSSID[6];
  // BSSID = the router we are connected to
  if(staMode){
    uint8_t* b = WiFi.BSSID();
    if(b) memcpy(apBSSID, b, 6);
    else  return;
  } else return;

  uint8_t ch = WiFi.channel();
  Serial.printf("[DEAUTH] Burst on ch=%d\n", ch);
  sendDeauthBurst(targetBytes, apBSSID, ch);
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

      String tm = "*BLOCKED DEVICE BACK*\n\n";
      tm += "Brand: *" + brand + "*\n";
      tm += "MAC: `" + macStr + "`\n";
      tm += "IP: `" + String(ip) + "`\n";
      tm += "Attempt: #" + String(devs[idx].blockHits) + "\n";
      tm += "Time: " + uptime() + "\n\n";
      tm += "_This device was previously blocked_\n";
      tm += "_and is trying to access your network again._\n\n";
      tm += "Dashboard: http://" + WiFi.localIP().toString();
      teleAlert(tm, true);

    } else if(!devs[idx].trusted) {
      // RICH INTRUDER ALERT
      addLog("INTRUDER: "+macStr+" @ "+String(ip)+" ["+brand+"]");

      // optional auto-blacklist
      if(autoBlacklist) {
        addBL(macStr);
        devs[idx].blocked = true;
      }

      threatLevel=2; threatMAC=macStr; threatIP=String(ip);
      threatInfo=brand+" UNKNOWN DEVICE";
      setAlarm(2);

      String tm = "*INTRUDER DETECTED!*\n\n";
      tm += "*Device Information*\n";
      tm += "  MAC: `" + macStr + "`\n";
      tm += "  IP: `" + String(ip) + "`\n";
      tm += "  Brand: *" + brand + "*\n";
      tm += "  Detected: " + uptime() + "\n\n";

      tm += "*Auto Actions Taken*\n";
      tm += (autoBlacklist?"  Added to blacklist\n":"  Flagged as unknown\n");
      tm += "  Alert logged\n";
      tm += "  LEDs and buzzer activated\n";
      if(deauthEnabled) tm += "  Manual Kick available in dashboard\n";
      tm += "\n";

      tm += "*URGENT SECURITY ADVICE*\n";
      tm += "Someone unknown joined your WiFi.\n";
      tm += "We strongly recommend:\n\n";
      tm += "  1. Change WiFi password NOW\n";
      tm += "  2. Use 16+ character password\n";
      tm += "  3. Mix letters, numbers, symbols\n";
      tm += "  4. Verify WPA2 or WPA3 enabled\n";
      tm += "  5. Disable WPS button on router\n";
      tm += "  6. Check router admin panel\n\n";
      tm += "Dashboard: http://" + WiFi.localIP().toString();
      teleAlert(tm, true);

    } else {
      Serial.println("[OK] "+macStr+" @ "+String(ip)+" ["+brand+"]");
    }
  } else {
    devs[idx].lastSeen=millis();
    devs[idx].trusted=inWL(devs[idx].mac);
    devs[idx].blocked=inBL(devs[idx].mac);

    if(devs[idx].trusted &&
       strcmp(devs[idx].ip,ip)!=0 &&
       strlen(devs[idx].ip)>0 &&
       millis()-devs[idx].firstSeen>60000) {
      String oldIP=String(devs[idx].ip);
      addLog("IP CHANGE: "+macStr+" "+oldIP+" -> "+String(ip));
      strncpy(devs[idx].prevIP,devs[idx].ip,15); devs[idx].prevIP[15]='\0';
      if(threatLevel==0 && notifyIPChange){
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

void wifiScanTick() {
  switch(wifiScanState) {
    case WS_REQUESTED: {
      if(WiFi.getMode()!=WIFI_AP_STA) WiFi.mode(WIFI_AP_STA);
      WiFi.scanDelete();
      WiFi.scanNetworks(true, false);
      wifiScanState = WS_RUNNING;
      Serial.println(F("[WiFi] Async scan started in AP_STA"));
      break;
    }
    case WS_RUNNING: {
      int n = WiFi.scanComplete();
      if(n == WIFI_SCAN_RUNNING) return;
      if(n < 0) {
        scanCount=0; scanCacheTime=millis();
        wifiScanState = WS_DONE;
        return;
      }
      int cnt = (n>MAX_NETS)?MAX_NETS:n;
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
  c+=".nav{display:flex;background:#080808;border-bottom:1px solid #141414;overflow-x:auto;white-space:nowrap}";
  c+=".nav a{flex:1;min-width:60px;padding:9px 4px;text-align:center;font-size:9px;color:#444;border-right:1px solid #141414;letter-spacing:1px}";
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
  c+=".bk{background:#1a0a1a;color:#cc44cc;border-color:#660066}";
  c+=".scanb{display:block;margin:0 12px 12px;background:#080e18;color:#4488cc;border:1px solid #1a3a55;padding:9px;border-radius:6px;text-align:center;font-family:monospace;font-size:12px;letter-spacing:1px}";
  c+="input,select,textarea{background:#060606;color:#bbb;border:1px solid #1f1f1f;padding:9px;border-radius:5px;width:100%;margin-top:8px;font-family:monospace;font-size:12px}";
  c+=".subm{background:#001a08;color:#00cc55;border:1px solid #004422;padding:10px;border-radius:5px;width:100%;margin-top:9px;font-family:monospace;font-size:12px;cursor:pointer}";
  c+=".subm.red{background:#1a0000;color:#cc4444;border-color:#660000}";
  c+=".subm.blue{background:#001a2a;color:#4488cc;border-color:#003355}";
  c+=".subm.purple{background:#1a0a1a;color:#cc44cc;border-color:#660066}";
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
  c+=".guide{background:#0a0e15;border-left:3px solid #4488cc;padding:10px;margin:10px 0;color:#888;font-size:11px;line-height:1.7}";
  c+=".guide b{color:#4488cc}";
  c+=".warn{background:#1a0500;border-left:3px solid #cc4444;padding:10px;margin:10px 0;color:#cc8888;font-size:11px;line-height:1.7}";
  c+=".lbl{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid #111}";
  c+=".lbl:last-child{border-bottom:none}";
  c+=".lbl span{flex:1}";
  c+=".tg{position:relative;display:inline-block;width:46px;height:24px}";
  c+=".tg input{display:none}";
  c+=".sl2{position:absolute;cursor:pointer;background:#222;top:0;left:0;right:0;bottom:0;border-radius:24px;transition:.3s}";
  c+=".sl2:before{position:absolute;content:'';height:18px;width:18px;left:3px;bottom:3px;background:#666;border-radius:50%;transition:.3s}";
  c+="input:checked+.sl2{background:#003322}";
  c+="input:checked+.sl2:before{transform:translateX(22px);background:#00cc55}";
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
  if(deauthActive){
    long left = (long)DEAUTH_DURATION_MS - (long)(millis()-deauthStartMs);
    if(left<0) left=0;
    h+="<div class='pill' style='color:#cc44cc;border-color:#660066;background:#1a0a1a'>";
    h+="KICK ACTIVE: "+deauthTargetMAC+" ("+String(left/1000)+"s left)";
    h+=" <a href='/stopkick' style='color:#ff8888'>STOP</a></div>";
  }
  h+="</div>";
  h+="<div class='nav'>";
  h+="<a href='/' class='"+(pg=="/"?String("on"):String(""))+"'>Monitor</a>";
  h+="<a href='/devices' class='"+(pg=="/devices"?String("on"):String(""))+"'>Devices</a>";
  h+="<a href='/wifi' class='"+(pg=="/wifi"?String("on"):String(""))+"'>WiFi</a>";
  h+="<a href='/notifications' class='"+(pg=="/notifications"?String("on"):String(""))+"'>Notify</a>";
  h+="<a href='/settings' class='"+(pg=="/settings"?String("on"):String(""))+"'>Settings</a>";
  h+="<a href='/log' class='"+(pg=="/log"?String("on"):String(""))+"'>Log</a>";
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
    long nxt=((long)scanIntervalMs-(long)(millis()-tLastScan))/1000;
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
    if(deauthEnabled && !devs[i].trusted){
      p+="<a class='btn bk' href='/kick?mac="+String(devs[i].mac)+"'>Kick</a>";
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
  p+="<div class='ftr'>IoT Sentinel v8.6 PRO | EIDIA UEMF 2025<br>Elmaghraoui Mouad &amp; Youssef Boutayeb</div>";
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
    if(deauthEnabled){
      p+="<a class='btn bk' href='/kick?mac="+String(devs[i].mac)+"'>Kick</a>";
    }
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
    if(deauthEnabled && idx!=-1){
      p+="<a class='btn bk' href='/kick?mac="+bl[i]+"'>Kick</a>";
    }
    p+="</div></div>";
  }
  if(blN==0) p+="<div style='color:#1e1e1e;font-size:12px;padding:8px 0'>Blacklist is empty.</div>";
  p+="</div>";

  p+="<div class='box'><div class='bh'>Manual MAC Entry</div>";
  p+="<form action='/trust' method='GET'><input type='text' name='mac' placeholder='AA:BB:CC:DD:EE:FF'>";
  p+="<button class='subm' type='submit'>Add to Whitelist</button></form>";
  p+="<form action='/block' method='GET' style='margin-top:10px'><input type='text' name='mac' placeholder='AA:BB:CC:DD:EE:FF'>";
  p+="<button class='subm red' type='submit'>Add to Blacklist</button></form></div>";
  p+="<div class='ftr'>IoT Sentinel v8.6 PRO</div>";
  p+="</body></html>";
  srv.send(200,"text/html; charset=UTF-8",p);
}

// ================================================================
//                  PAGE: /wifi  (AP-safe)
// ================================================================
void handleWiFi() {
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
  p+="<div class='guide'>";
  p+="<b>Tip:</b> This device works on any WiFi - your home router OR your phone's hotspot. ";
  p+="Just select the network and enter the password.";
  p+="</div>";

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
  p+="<input id='sid' type='text' name='ssid' placeholder='Network Name (or hotspot name)' value='"+String(cfgSSID)+"'>";
  p+="<input id='pw' type='password' name='pass' placeholder='Password (leave empty if open)'>";
  p+="<button class='subm' type='submit'>Connect &amp; Start Guarding</button>";
  p+="</form></div>";
  p+="<div class='ftr'>Settings saved to EEPROM -- survives reboot</div>";
  p+="</body></html>";
  srv.send(200,"text/html; charset=UTF-8",p);
}

// ================================================================
//                       PAGE: /notifications
// ================================================================
void handleNotifications() {
  String col="#4488cc";
  String bg ="#060c14";

  String p="";
  p+="<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  p+="<meta name='viewport' content='width=device-width,initial-scale=1'>";
  p+="<title>Notifications</title><style>"+getCSS(col,bg)+"</style></head><body>";
  p+=hdrNav(col,"/notifications");

  p+="<div class='box'><div class='bh'>Telegram Notifications</div>";
  p+="<div style='color:#888;font-size:11px;margin-bottom:8px'>";
  bool configured = (strlen(botToken)>=10 && strlen(chatId)>=3);
  p+= configured ? String("Status: <span style='color:#00cc55'>Configured</span>")
                 : String("Status: <span style='color:#cc4444'>Not configured</span>");
  p+="</div>";

  p+="<form action='/savenotify' method='POST'>";
  p+="<div style='color:#666;font-size:10px;margin-top:8px'>BOT TOKEN</div>";
  p+="<input type='text' name='token' value='"+String(botToken)+"' placeholder='12345:ABC...' maxlength='79'>";
  p+="<div style='color:#666;font-size:10px;margin-top:8px'>CHAT ID (your user id)</div>";
  p+="<input type='text' name='chat' value='"+String(chatId)+"' placeholder='5401312485' maxlength='23'>";
  p+="<button class='subm' type='submit'>Save</button>";
  p+="</form>";

  p+="<form action='/testnotify' method='GET' style='margin-top:6px'>";
  p+="<button class='subm blue' type='submit'>Send Test Message</button>";
  p+="</form>";

  p+="<div class='guide' style='margin-top:14px'>";
  p+="<b>How to set up Telegram alerts</b><br><br>";
  p+="<b>1.</b> Open Telegram and search for <b>@BotFather</b><br>";
  p+="<b>2.</b> Send <b>/newbot</b> and follow the prompts<br>";
  p+="<b>3.</b> Copy the bot token shown - paste above<br>";
  p+="<b>4.</b> Search <b>@userinfobot</b>, send /start<br>";
  p+="<b>5.</b> Copy the Id shown - paste above<br>";
  p+="<b>6.</b> Open chat with YOUR new bot and send /start<br>";
  p+="<b>7.</b> Click <b>Save</b> then <b>Send Test Message</b>";
  p+="</div>";

  p+="</div>";

  p+="<div class='box'><div class='bh'>WhatsApp (Coming in v9.0)</div>";
  p+="<div style='color:#444;font-size:11px;padding:8px 0'>";
  p+="WhatsApp notifications via CallMeBot will be available in the next firmware update. ";
  p+="You will be able to receive alerts on WhatsApp without installing any app.";
  p+="</div></div>";

  p+="<div class='ftr'>IoT Sentinel v8.6 PRO</div>";
  p+="</body></html>";
  srv.send(200,"text/html; charset=UTF-8",p);
}

// ================================================================
//                       PAGE: /settings
// ================================================================
void handleSettings() {
  String col="#4488cc";
  String bg ="#060c14";

  String p="";
  p+="<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  p+="<meta name='viewport' content='width=device-width,initial-scale=1'>";
  p+="<title>Settings</title><style>"+getCSS(col,bg)+"</style></head><body>";
  p+=hdrNav(col,"/settings");

  p+="<form action='/savesettings' method='POST'>";

  p+="<div class='box'><div class='bh'>Detection Settings</div>";
  p+="<div class='lbl'><span>Auto-Blacklist Intruders<br>";
  p+="<small style='color:#555'>Automatically blacklist any unknown device</small></span>";
  p+="<label class='tg'><input type='checkbox' name='autobl'"+(autoBlacklist?String(" checked"):String(""))+"><span class='sl2'></span></label>";
  p+="</div>";
  p+="<div class='lbl'><span>Notify on IP Change<br>";
  p+="<small style='color:#555'>Send alert when trusted device IP changes</small></span>";
  p+="<label class='tg'><input type='checkbox' name='ipchg'"+(notifyIPChange?String(" checked"):String(""))+"><span class='sl2'></span></label>";
  p+="</div>";
  p+="<div style='color:#666;font-size:10px;margin-top:10px'>SCAN INTERVAL</div>";
  p+="<select name='interval'>";
  p+="<option value='60'"  +(scanIntervalMs==60000UL ?String(" selected"):String(""))+">60 seconds (aggressive)</option>";
  p+="<option value='90'"  +(scanIntervalMs==90000UL ?String(" selected"):String(""))+">90 seconds (default)</option>";
  p+="<option value='300'" +(scanIntervalMs==300000UL?String(" selected"):String(""))+">5 minutes (relaxed)</option>";
  p+="</select>";
  p+="</div>";

  p+="<div class='box' style='border-color:#660066'>";
  p+="<div class='bh' style='color:#cc44cc'>Manual Kick (Deauth)</div>";
  p+="<div class='warn'>";
  p+="<b>LEGAL WARNING</b><br>";
  p+="Sending 802.11 deauthentication frames may be illegal in your country if used on networks you do not own. ";
  p+="By enabling this you agree:<br>";
  p+="- You own or administer this WiFi network<br>";
  p+="- You are solely responsible for legal compliance<br>";
  p+="- You understand brief radio interference may occur<br>";
  p+="- Each use requires manual per-target confirmation";
  p+="</div>";
  p+="<div class='lbl'><span>Enable Kick Button<br>";
  p+="<small style='color:#555'>When ON: a Kick button appears on each unknown device.<br>";
  p+="Each click requires explicit confirmation.</small></span>";
  p+="<label class='tg'><input type='checkbox' name='deauth'"+(deauthEnabled?String(" checked"):String(""))+"><span class='sl2'></span></label>";
  p+="</div>";
  p+="<div style='color:#666;font-size:10px;margin-top:8px;line-height:1.7'>";
  p+="Kick mode: <b>Mode 3 - Aggressive</b> (60s of deauth frames at 3s intervals)<br>";
  p+="Effect: target device will be unable to stay connected for 60 seconds<br>";
  p+="Auto-stops after 60 seconds or click STOP at any time";
  p+="</div>";
  p+="</div>";

  p+="<button class='subm' type='submit'>Save Settings</button>";
  p+="</form>";

  p+="<form action='/factoryreset' method='POST' onsubmit=\"return confirm('Erase ALL settings, whitelist, blacklist, and credentials? This cannot be undone.');\">";
  p+="<button class='subm red' type='submit'>Factory Reset</button>";
  p+="</form>";

  p+="<div class='ftr'>IoT Sentinel v8.6 PRO</div>";
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
  p+="<div class='ftr'>Auto-refresh 15s | IoT Sentinel v8.6 PRO</div>";
  p+="</body></html>";
  srv.send(200,"text/html; charset=UTF-8",p);
}

// ================================================================
//                  KICK CONFIRMATION PAGE
// ================================================================
void handleKickConfirm() {
  String col="#cc44cc";
  String bg ="#0a0a14";
  if(!srv.hasArg("mac")){ srv.sendHeader("Location","/devices"); srv.send(302,"",""); return; }
  String mac = srv.arg("mac"); mac.toUpperCase();

  if(srv.hasArg("confirm") && srv.arg("confirm")=="yes") {
    if(!deauthEnabled){
      srv.send(200,"text/html; charset=UTF-8",
        "<html><body style='background:#1a0000;color:#cc4444;font-family:monospace;padding:30px'>"
        "Kick feature is DISABLED.<br><br>"
        "Enable it first in <a href='/settings' style='color:#4488cc'>Settings</a>."
        "</body></html>");
      return;
    }
    startDeauth(mac);
    srv.sendHeader("Location","/");
    srv.send(302,"","");
    return;
  }

  String p="<!DOCTYPE html><html><head><meta charset='UTF-8'>";
  p+="<meta name='viewport' content='width=device-width,initial-scale=1'>";
  p+="<title>Confirm Kick</title><style>"+getCSS(col,bg)+"</style></head><body>";
  p+=hdrNav(col,"/devices");

  p+="<div class='box' style='border-color:#660066'>";
  p+="<div class='bh' style='color:#cc44cc'>Confirm Manual Kick</div>";

  if(!deauthEnabled){
    p+="<div class='warn'>The Kick feature is currently DISABLED.<br>";
    p+="Enable it first in <a href='/settings' style='color:#4488cc'>Settings</a>.</div>";
    p+="</div></body></html>";
    srv.send(200,"text/html; charset=UTF-8",p);
    return;
  }

  p+="<div style='padding:8px 0;color:#bbb;font-size:13px'>Target MAC:</div>";
  p+="<div style='font-family:monospace;font-size:18px;color:#ff8888;padding:6px 0'>"+mac+"</div>";

  p+="<div class='warn' style='margin-top:14px'>";
  p+="<b>LEGAL DISCLAIMER</b><br><br>";
  p+="This action sends 802.11 deauthentication frames for 60 seconds. ";
  p+="The target device will be unable to stay connected during this time.<br><br>";
  p+="<b>This may be illegal in your country</b> if used on networks you do not own or administer.<br><br>";
  p+="By clicking <b>Confirm Kick</b> you agree:<br>";
  p+="- You own or administer this WiFi network<br>";
  p+="- You are responsible for legal compliance<br>";
  p+="- You understand 60 seconds of radio interference will occur<br>";
  p+="- The target may be a legitimate guest";
  p+="</div>";

  p+="<form action='/kick' method='GET'>";
  p+="<input type='hidden' name='mac' value='"+mac+"'>";
  p+="<input type='hidden' name='confirm' value='yes'>";
  p+="<button class='subm purple' type='submit'>Confirm Kick (60s)</button>";
  p+="</form>";
  p+="<form action='/devices' method='GET' style='margin-top:6px'>";
  p+="<button class='subm' type='submit'>Cancel</button>";
  p+="</form>";

  p+="</div></body></html>";
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

  Serial.println(F("\n+=====================================+"));
  Serial.println(F(  "|  IoT Sentinel v8.6 PRO              |"));
  Serial.println(F(  "|  Configurable + Manual Kick         |"));
  Serial.println(F(  "|  Mouad & Youssef | EIDIA UEMF 2025  |"));
  Serial.println(F(  "+=====================================+"));

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

    dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
    dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
    Serial.println(F("[DNS] Captive-portal DNS active"));
  }

  if(staMode){
    teleClient.setInsecure();
    bot.updateToken(String(botToken));

    String myMAC=WiFi.macAddress(); myMAC.toUpperCase();
    addWL(myMAC);
    Serial.println("[WL] Auto-trusted self: "+myMAC);

    String bm="*IoT Sentinel v8.6 Online*\n\n";
    bm+="Network: `"+WiFi.SSID()+"`\n";
    bm+="IP: `"+WiFi.localIP().toString()+"`\n";
    bm+="Dashboard: http://"+WiFi.localIP().toString()+"\n";
    bm+="Trusted: "+String(wlN)+" | Blocked: "+String(blN)+"\n";
    bm+="Auto-Blacklist: "+(autoBlacklist?String("ON"):String("OFF"))+"\n";
    bm+="Manual Kick: "+(deauthEnabled?String("ENABLED"):String("disabled"))+"\n\n";
    bm+="Watching your network 24/7";
    teleAlert(bm,true);
  }

  const char* HDRS[] = { "Referer" };
  srv.collectHeaders(HDRS, sizeof(HDRS)/sizeof(HDRS[0]));

  // ---------------- CORE ROUTES ----------------
  srv.on("/",              HTTP_GET,  handleRoot);
  srv.on("/devices",       HTTP_GET,  handleDevices);
  srv.on("/wifi",          HTTP_GET,  handleWiFi);
  srv.on("/notifications", HTTP_GET,  handleNotifications);
  srv.on("/settings",      HTTP_GET,  handleSettings);
  srv.on("/log",           HTTP_GET,  handleLog);

  srv.on("/savenotify", HTTP_POST, [](){
    if(srv.hasArg("token")) {
      String t = srv.arg("token"); t.trim();
      if(t.length()>=10 && t.length()<=79) {
        strncpy(botToken, t.c_str(), 79); botToken[79]='\0';
      }
    }
    if(srv.hasArg("chat")) {
      String c = srv.arg("chat"); c.trim();
      if(c.length()>=3 && c.length()<=23) {
        strncpy(chatId, c.c_str(), 23); chatId[23]='\0';
      }
    }
    eeSave();
    if(staMode) bot.updateToken(String(botToken));
    srv.sendHeader("Location","/notifications"); srv.send(302,"","");
  });

  srv.on("/testnotify", HTTP_GET, [](){
    if(staMode){
      String tm="*Test Message*\n\n";
      tm+="If you can read this, your IoT Sentinel\n";
      tm+="notifications are working correctly.\n\n";
      tm+="Time: "+uptime()+"\n";
      tm+="IP: `"+WiFi.localIP().toString()+"`\n";
      tm+="Network: `"+WiFi.SSID()+"`";
      teleAlert(tm,true);
    }
    srv.sendHeader("Location","/notifications"); srv.send(302,"","");
  });

  srv.on("/savesettings", HTTP_POST, [](){
    autoBlacklist  = srv.hasArg("autobl");
    notifyIPChange = srv.hasArg("ipchg");
    deauthEnabled  = srv.hasArg("deauth");
    if(srv.hasArg("interval")){
      int sec = srv.arg("interval").toInt();
      scanIntervalMs = (sec==60)?60000UL:(sec==300)?300000UL:90000UL;
    }
    eeSave();
    srv.sendHeader("Location","/settings"); srv.send(302,"","");
  });

  srv.on("/factoryreset", HTTP_POST, [](){
    EEPROM.begin(EE_SIZE);
    for(int i=0;i<EE_SIZE;i++) EEPROM.write(i, 0xFF);
    EEPROM.commit();
    EEPROM.end();
    srv.send(200,"text/html; charset=UTF-8",
      "<html><body style='background:#000;color:#0c5;font-family:monospace;padding:40px;text-align:center'>"
      "Factory reset complete.<br>Rebooting...</body></html>");
    delay(800);
    ESP.restart();
  });

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
    j+=",\"deauthActive\":"+String(deauthActive?"true":"false");
    j+=",\"deauthTarget\":\""+deauthTargetMAC+"\"";
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

  srv.on("/kick",     HTTP_GET, handleKickConfirm);

  srv.on("/stopkick", HTTP_GET, [](){
    stopDeauth("user pressed STOP");
    srv.sendHeader("Location","/"); srv.send(302,"","");
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
  srv.on("/generate_204",        HTTP_GET, [](){ srv.sendHeader("Location","/"); srv.send(302,"",""); });
  srv.on("/gen_204",             HTTP_GET, [](){ srv.sendHeader("Location","/"); srv.send(302,"",""); });
  srv.on("/hotspot-detect.html", HTTP_GET, [](){ srv.send(200,"text/html","<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"); });
  srv.on("/library/test/success.html",HTTP_GET, [](){ srv.send(200,"text/html","<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"); });
  srv.on("/connecttest.txt",     HTTP_GET, [](){ srv.send(200,"text/plain","Microsoft Connect Test"); });
  srv.on("/ncsi.txt",            HTTP_GET, [](){ srv.send(200,"text/plain","Microsoft NCSI"); });
  srv.on("/canonical.html",      HTTP_GET, [](){ srv.sendHeader("Location","/"); srv.send(302,"",""); });
  srv.on("/success.txt",         HTTP_GET, [](){ srv.send(200,"text/plain","success"); });

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
  if(!staMode) dnsServer.processNextRequest();
  wifiScanTick();
  deauthTick();    // <-- handles active kick attacks

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

  // skip LAN scan while deauth is firing (radio is busy)
  if(staMode && !scanning && !deauthActive && millis()-tLastScan>=scanIntervalMs){
    tLastScan=millis(); runScan();
  }

  static unsigned long lastARP=0;
  if(staMode && !scanning && !deauthActive && millis()-lastARP>=8000){
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
