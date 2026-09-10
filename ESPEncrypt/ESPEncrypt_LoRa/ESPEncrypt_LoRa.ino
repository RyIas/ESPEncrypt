#include <esp_mac.h>   // for esp_read_mac() to get device mac.
#include <Crypto.h>
#include <Curve25519.h>
#include <ChaChaPoly.h>
#include <RNG.h>
#include <SHA256.h>
#include <Preferences.h> 
#include <TFT_eSPI.h>
#include <XPT2046_Touchscreen.h>

#define T_IRQ 36
#define T_MOSI 32
#define T_MISO 39
#define T_CLK 25
#define T_CS 33

Preferences pref;
SPIClass TouchSPI = SPIClass(VSPI);
XPT2046_Touchscreen TS(T_CS,T_IRQ);
TFT_eSPI tft = TFT_eSPI();
ChaChaPoly chacha;
SHA256 hasher; 

// ---- LR32 UART transport ----
#define LoRaRX 27 // LoRaRx pin -> DX-LR32 TX pin
#define LoRaTX 22 // LoRaTx pin -> DX-LR32 RX pin
HardwareSerial LoRaSerial(2);


//UK Laws govern that 868Mhz is the best frequency. This is channel 0x12 in the DX-LR32. Use your countries law and UART LoRa spec sheet (if not a DX-LR32) to change accordingly.
//must match on both devices.
#define LORA_CHANNEL 0x12

// Must match on both devices. Disable if your UART doesnt support RSSI as last byte. 
#define LORA_RSSI_ENABLED true

//Comfortably under the modules 230 byte subpacket FIFO limit. Largest packet is TextPacket plus our own 1-byte length prefix tops out well under this.
#define MAX_LORA_PACKET 200

// used as the mac. 
uint8_t myDeviceId[6];

//stores keys from NVG later on.
uint8_t myPrivateKey[32]; 
uint8_t myPublicKey[32];
String Username; //NOTE: String != char

//protocol definitions, will be used for the logic.
#define MODE_IDLE -1 //do nothing
#define MODE_DISCOVERING 0 //search for all devices 
#define MODE_PENDING 1  //entered when sent pair request first. used to check if we need to respond to a pairRequestPacket in onDataRecv.
#define MODE_PAIRING 2   //entered when all hashes are complete and now shows screen with pair codes. Original recvier of pair reuqest enters this stage immediatly because it can calc all keys before waiting on response. no need to pend.
#define MODE_CHATTING 3 //c
#define MODE_RECONNECTING 4 //used when reconneting to previous pair.

int deviceMode = MODE_IDLE;

//screen definitions, will be used for touch handling
#define SCREEN_USERNAME_INIT   0
#define SCREEN_DISCOVERY       1
#define SCREEN_KEYBOARD        2
#define SCREEN_SETTINGS        3
#define SCREEN_FACTORY_RESET   4
#define SCREEN_PAIRED_DEVICES  5
#define SCREEN_BLOCKED_DEVICES 6
#define SCREEN_PAIR_CODES      7
#define SCREEN_CHAT            8
#define SCREEN_POPUP           9

//screen definitions so that keyboard can go back to old screen
int currentScreen = SCREEN_USERNAME_INIT;
int keyboardReturnScreen = SCREEN_USERNAME_INIT;

volatile const char* popupText = "";
volatile int popupReturnScreen = SCREEN_DISCOVERY;
volatile int popupColour = TFT_WHITE;

//used for list pages
bool leftArrowActive = false;
bool rightArrowActive = false;

// KEY TYPE DEFINITIONS
#define KB 0
#define KB_BACKSPACE 1
#define KB_ENTER 2
#define KB_SHIFT 3
#define KB_PAGE 4
#define KB_SPACE 5

volatile bool confirmHashReceived = false;

//used so that if one user presses pair and sends matching code, it wont just pair on your device if you haven't pressed pair.
volatile bool sentOwnConfirm = false;
volatile bool peerConfirmRecieved = false;
volatile bool isReconnecting = false;

uint8_t peerConfirmHash[32];

uint8_t pairingMac[6] = {};        // who we are pairing with
char pairingUsername[16] = {};  // saves username too
uint8_t pairingPublicKey[32] = {}; //
uint8_t theirRandNum[16] = {};
bool theirReconnection = false;

uint8_t myRandNum[16] = {};

uint8_t sessionKey[32] = {};  //the actual encryption key.
char pairingCodeStr[8] = {};   // holds full string of pairing codes "123 456\0" so i can just do tft.print(pairingCodeSrt);

uint8_t abortValue[32] = {}; //hash sent in PairAbortPacket if cancel/block pressed.
uint8_t confirmValue[32] = {}; // the hash sent in PairConfirmPacket if pair pressed.

bool awaitingPairAck = false;
uint8_t pendingPairPacket[80];
uint8_t pendingPairPacketLen = 0;
uint8_t pendingPairExpectedAck[32] = {};
unsigned long pendingPairNextSend = 0;
int pendingPairAttempts = 0;

uint16_t userColours[18] = {TFT_NAVY, TFT_DARKCYAN, TFT_MAROON, TFT_PURPLE, TFT_OLIVE, TFT_LIGHTGREY, TFT_BLUE, TFT_CYAN, TFT_MAGENTA, TFT_YELLOW, TFT_ORANGE, TFT_GREENYELLOW, TFT_PINK, TFT_BROWN, TFT_GOLD, TFT_SILVER, TFT_SKYBLUE, TFT_VIOLET};


#define MSG_DISCOVERY 0
#define MSG_PAIR_REQUEST 1
#define MSG_CONFIRM 2
#define MSG_TEXT 3
#define MSG_ABORT 4
#define MSG_ACK 5
#define MSG_PAIR_ACK 6

#define ABORT_CANCEL 1
#define ABORT_BLOCK 2

// all types of packet types defined as structures. 

typedef void (*RowActionFn)(int deviceIndex); // new way for using pointers. defines pointer RowAction and takes paremeter deviceIndex. 

//always sent own MAC adress in all packets so other user knows who its coming from. this mimics info->src_addr used to be checked before decoding under ESP-NOW.

typedef struct {
  uint8_t type; // MSG_DISCOVERY 
  uint8_t senderId[6];
  char username[16];
  uint8_t publicKey[32];
} DiscoveryPacket; 

typedef struct {
  uint8_t type; // MSG_PAIR_REQUEST
  uint8_t senderId[6];
  bool currentlyPaired;
  char username[16];
  uint8_t publicKey[32];
  uint8_t randNum[16];
} PairRequestPacket;  

typedef struct {
  uint8_t type; // MSG_CONFIRM
  uint8_t senderId[6];
  uint8_t hash[32];
} PairConfirmPacket; 

typedef struct {
  uint8_t type; // MSG_ABORT
  uint8_t senderId[6];
  uint8_t abortType;
  uint8_t hash[32];
} PairAbortPacket; 

typedef struct {
  uint8_t type;             // MSG_TEXT
  uint8_t senderId[6];
  uint8_t encryptSalt[12];   // per-message nonce
  uint8_t polyTag[16];      // ChaChaPoly auth tag
  uint8_t cipherText[126];
} TextPacket;

typedef struct {
  uint8_t type; // MSG_ACK
  uint8_t senderId[6];
  uint8_t hash[32];
} AckPacket;

typedef struct {
  uint8_t type;        // MSG_PAIR_ACK
  uint8_t senderId[6];
  uint8_t hash[32];
} PairAckPacket;


// holds the info of an external device.
typedef struct {
  //used for all 3.
  uint8_t mac[6];
  char username[16];
  uint8_t publicKey[32];

  //used for discoveredDevices:
  unsigned long lastSeen;
  int8_t rssi;
} ExternalDevice;

///device list stuff

#define MAX_DISCOVERED 12
#define MAX_PAIRED 24
#define MAX_BLOCKED 24

ExternalDevice discoveredDevices[MAX_DISCOVERED]; //makes 10 structures of ExternalDevice
int discoveredCount = 0; // a counter of devices currently nearby
int deviceListScroll = 0; //starting array of discovered devices.

ExternalDevice pairedDevices[MAX_PAIRED];
int pairedCount = 0;
int pairedListScroll = 0;

ExternalDevice blockedDevices[MAX_BLOCKED];
int blockedCount = 0;
int blockedListScroll = 0;

struct DeviceListConfig {
  const char* title;        // header text, e.g. "Discovery Mode:"
  bool isDiscoveryList;
  ExternalDevice* devices;
  int* count;
  int* scroll;
  char cornerSymbol;        // '*' for settings gear, '<' for back arrow
  int cornerTarget;         // screen to switch to when corner button tapped
  int colour;
};

DeviceListConfig discoveryConfig = { "Discovery Mode:", true, discoveredDevices, &discoveredCount, &deviceListScroll, '*', SCREEN_SETTINGS, TFT_WHITE};
DeviceListConfig pairedConfig    = { "Paired Devices:",  false, pairedDevices, &pairedCount, &pairedListScroll, '<', SCREEN_SETTINGS, TFT_GREEN};
DeviceListConfig blockedConfig   = { "Blocked Devices:", false, blockedDevices, &blockedCount, &blockedListScroll, '<', SCREEN_SETTINGS, TFT_ORANGE };


unsigned long lastBroadcastTime = 0; 
unsigned long nextBroadcastTime = 0; // replaces the flat "> 10000" check
unsigned long lastRemoveCheck = 0; //used for removing devices no longer availible in discovery
unsigned long pendingStartTime = 0; // used to escape MODE_PENDING.
unsigned long popupStartTime = 0; // used to close popup

bool updateDiscoveryScreen = false;
bool needsPairScreenRedraw = false;
bool updatePairedScreen = false;
bool updateBlockedScreen = false;
bool updateSignal = false;
bool updatePopup = false;

// chat stuff

#define MAX_MESSAGES 400

typedef struct {
  char text[126];
  bool fromMe;
} StoredMessage;

StoredMessage chatHistory[MAX_MESSAGES];
int messageCount = 0;

//same info as pairingMac, pairingUsername and pairingPublickey but moves so resetPairingState() won't clear it.
uint8_t chatPeerMac[6] = {};
char chatPeerUsername[16] = {};
uint8_t chatPeerPublicKey[32] = {};

#define CHAT_CHARS_PER_LINE (310 / (6 * 2))   //text page viewport at text size 2 (width / char width * 2) 
#define CHAT_LINES_PER_PAGE (144 / (8 * 2))   //same but for height

int chatScroll = 0;
bool updateChatScreen = false;

// ack packets stuff:

#define MAX_SEND_ATTEMPTS 5
#define ACK_TIMEOUT 3000 // ms between resend attempts
#define ACK_JITTER_MAX 4000

unsigned long pendingRetryDelay = 0; 

//stores text packet temporarily until acknowledgment packet recieved.
bool awaitingAck = false;
TextPacket pendingPacket = {};
int pendingPacketLen = 0;
uint8_t pendingExpectedAck[32] = {}; //what a valid ack for the pending message must equal
unsigned long pendingLastSendTime = 0;
int pendingAttempts = 0;
uint8_t lastAcceptedTag[16] = {};
bool hasLastAcceptedTag = false;
bool lastAckedMsgValid = false;

// KEYBOARD STUFF 
// KEYBOARD VARIABLES THAT DO NOT NEED TO BE CHANGED !!!!!!!!!!!!!!!!!!!!!!!!!!!!

bool shiftOn = false; //starts with caps lock off
bool secondPage = false; //and on first page
const int startX = 0;
const int startY = 95; //was 100
const int keyW = 26;  // 320 / 10 keys
const int keyH = 40;

//where the rows start, you must also change the code in drawKeyboard() if you want to change this
const int row0offset = 4;
const int row1offset = 17;
const int row2offset = 4;

//important for keyboard functions.
unsigned long lastTouchTime = 0;

//underscore 4 keyboard
unsigned long lastBlinkTime = 0;
bool underscoreOn = true;
int charX = 0;
int charY = 0;

char typedText[121];  // array that holds all of the characters
int typedIndex = 0;   // how many characters typed so far

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// The exception, do not change here but change in code depending on max chars allowed.
int maxChars = 125;

// CHARACTER INITIALISATIONS ------------------------------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct {
  char label;
  int action;
  int sizeMult;
} Key;


Key row0[11] = {
  { 'q', KB, 1 }, { 'w', KB, 1 }, { 'e', KB, 1 }, { 'r', KB, 1 }, { 't', KB, 1 }, { 'y', KB, 1 }, { 'u', KB, 1 }, { 'i', KB, 1 }, { 'o', KB, 1 }, { 'p', KB, 1 }, { '<', KB_BACKSPACE, 2 }
};

Key row1[10] = {
  { 'a', KB, 1 }, { 's', KB, 1 }, { 'd', KB, 1 }, { 'f', KB, 1 }, { 'g', KB, 1 }, { 'h', KB, 1 }, { 'j', KB, 1 }, { 'k', KB, 1 }, { 'l', KB, 1 }, { '>', KB_ENTER, 2 } 
};

Key row2[9] = {
  {'^', KB_SHIFT , 2}, {'z', KB , 1}, {'x', KB , 1 }, {'c', KB , 1 }, {'v', KB , 1 }, {'b', KB , 1 }, {'n', KB , 1 }, {'m', KB , 1 }, {'|', KB_PAGE , 3 }
};

// PAGE 2 --------------------------------------------------------------------------------------------------------------------------------------------------------------
Key row0_page2[11] = {
  { '1', KB, 1 }, { '2', KB, 1 }, { '3', KB, 1 }, { '4', KB, 1 }, { '5', KB, 1 }, { '6', KB, 1 }, { '7', KB, 1 }, { '8', KB, 1 }, { '9', KB, 1 }, { '0', KB, 1 }, { '<', KB_BACKSPACE, 2 }
};

Key row1_page2[10] = {
  { '#', KB, 1 }, { '\'', KB, 1 }, { '/', KB, 1 }, { '*', KB, 1 }, { '(', KB, 1 }, { ')', KB, 1 }, { '@', KB, 1 }, { '&', KB, 1 }, { '$', KB, 1 }, { '>', KB_ENTER, 2 } 
};

Key row2_page2[9] = {
  {'^', KB_SHIFT , 2}, {'!', KB , 1}, {'?', KB , 1 }, {'.', KB , 1 }, {',', KB , 1 }, {'+', KB , 1 }, {'-', KB , 1 }, {'=', KB , 1 }, {'|', KB_PAGE , 3 }
};


Key* rowPointer[3] = {
  row0,
  row1,
  row2
};


int rowSizes[3]{
  11,
  10,
  9
};


//prototype declerations since Arduino IDE is being weird:

void drawScreen(int);
void charsDisplayed();
void drawKeyboard();
void startkeyboard(int, int);


//---Function definitions----


//25 max chars pop up and its stuff
void popup(const char* text, int returnScreen, int colour){
  int borderSize = strlen(text) * 6 * 2 + 20;
  tft.setTextSize(2);
  tft.setTextColor(colour);

  tft.fillRect(160 - borderSize/2, 90, borderSize, 60, TFT_BLACK);
  tft.drawRect(160 - borderSize/2, 90, borderSize, 60, colour);

  tft.setCursor(160 - strlen(text) * 6 * 2 / 2, 112);
  tft.print(text);

  tft.setTextColor(TFT_WHITE);

  popupReturnScreen = returnScreen;
  popupStartTime = millis();
  currentScreen = SCREEN_POPUP;
}


//LOGIC stuff

void processIncomingPacket(const uint8_t *data, int len, int8_t rssi) {

  int incomingType = data[0]; //checks first byte of incoming packet == uint8_t type;

  switch (incomingType) {

    case MSG_DISCOVERY: {
      if (len != sizeof(DiscoveryPacket)) break; //quick check between recv data len and size of structure.

      //copies actual data sent
      DiscoveryPacket incoming = {}; 
      memcpy(&incoming, data, sizeof(incoming));

      if (isBlocked(incoming.senderId, incoming.username, incoming.publicKey)) break; //if its a blocked device, dont read it.

      //------- Code for checking if device has been previously discovered or not and to save their info ---------------

      int existingIndex = -1; //presumes that discovered device is not in the existing index.

      for(int i=0; i < discoveredCount; i++){ // goes from i=0 all the way up to however many discovered devices there are to check if this mac is any of the alr stored ones.
        if(memcmp(discoveredDevices[i].mac,incoming.senderId,6)==0){ //compares the mac address against stored ones
          existingIndex = i; //if alr discovered it makes existingIndex = i. This is so we can save the local i value of which exact array the recieved device's stored on. (used at 2nd if statement down)
          break; 
        }
      }

      if(existingIndex == -1 && discoveredCount < MAX_DISCOVERED){
        existingIndex = discoveredCount;
        discoveredCount++;
        updateDiscoveryScreen = true; //only refreshes page if in discovery menu
      }

      if(existingIndex != -1){ //if its not -1 update the new discoveredDevices[existingIndex] value. Useful as also updates already seen devices. If a device is factory reset it's MAC is not so it's good to update info.
        memcpy(discoveredDevices[existingIndex].mac,incoming.senderId,6);
        memcpy(discoveredDevices[existingIndex].username,incoming.username,16);
        memcpy(discoveredDevices[existingIndex].publicKey,incoming.publicKey,32);
        discoveredDevices[existingIndex].lastSeen = millis();
        discoveredDevices[existingIndex].rssi = rssi;
        Serial.println(rssi);
      }
        break;
    }

    case MSG_PAIR_REQUEST: {
      if (len != sizeof(PairRequestPacket)) break; //breaks if length is wrong 

      PairRequestPacket incoming = {};
      memcpy(&incoming, data, sizeof(incoming));

      if(isBlocked(incoming.senderId, incoming.username, incoming.publicKey)) break; //if its a blocked device, dont read it. 

      //Checks if this is a response to our sent packet, or if its a new packet. If the device is in pending mode and the pairingMac array matches the recieved one, it's a response.
      bool isThisAResponse = (deviceMode == MODE_PENDING && memcmp(pairingMac, incoming.senderId, 6) == 0);


      // Situation : WE HAVE RECIEVED A PAIR PACKET FROM A DEVICE WE DONT KNOW:
      if (isThisAResponse == false){ 
        //breaks if not in discovery mode and recieve a new packet.
        if(deviceMode != MODE_DISCOVERING) break;

        //copies all data recieved down as its a new pairing packet
        memcpy(pairingMac, incoming.senderId, 6);
        theirReconnection = incoming.currentlyPaired;
        memcpy(pairingUsername, incoming.username, 16);
        memcpy(pairingPublicKey, incoming.publicKey, 32);
        memcpy(theirRandNum, incoming.randNum, 16);

        for(int i = 0; i < 16; i++) myRandNum[i] = esp_random() & 0xFF;

        PairRequestPacket outgoing = {};

        outgoing.type = MSG_PAIR_REQUEST;
        memcpy(outgoing.senderId, myDeviceId, 6);
        outgoing.currentlyPaired = isPaired(pairingMac, pairingUsername, pairingPublicKey); //new
        Username.toCharArray(outgoing.username, 16);
        memcpy(outgoing.publicKey, myPublicKey, 32);
        memcpy(outgoing.randNum, myRandNum, 16);

        //sends out response pair packet.
        sendLoRa((uint8_t*)&outgoing, sizeof(outgoing));

        derivePairingHashes();
        deviceMode = MODE_PAIRING;
        currentScreen = SCREEN_PAIR_CODES;
        needsPairScreenRedraw = true;
      }
      
      //Situation: WE HAVE RECIEVED A RESPONSE PAIR PACKET!!:
      else if(isThisAResponse == true){
        memcpy(theirRandNum, incoming.randNum, 16);
        theirReconnection = incoming.currentlyPaired;

        derivePairingHashes();
        deviceMode = MODE_PAIRING;
        currentScreen = SCREEN_PAIR_CODES;
        needsPairScreenRedraw = true;
      }
      break;
    }

    case MSG_CONFIRM: {

      //checks size of packet is correct, device is in pairing mode and that the recieved mac is the same as the current pairing mac.
      if (len != sizeof(PairConfirmPacket)) break;
      if (deviceMode != MODE_PAIRING) break;
      if (memcmp(data + 1, pairingMac, 6) != 0) break;

      PairConfirmPacket incoming = {};
      memcpy(&incoming, data, sizeof(incoming)); 
      
      //ack
      uint8_t ackVal[32];
      computePairAckValue(incoming.hash, ackVal);
      PairAckPacket ack = {};
      ack.type = MSG_PAIR_ACK;
      memcpy(ack.senderId, myDeviceId, 6);
      memcpy(ack.hash, ackVal, 32);
      sendLoRa((uint8_t*)&ack, sizeof(ack));

      //saves incoming hash to global variable.
      memcpy(peerConfirmHash, incoming.hash, 32);

      //sets peerConfirmRecvied to true for the pairing function.
      peerConfirmRecieved = true;

      tryPairing();
    
      break;
    }

    case MSG_ABORT:{
      if (len != sizeof(PairAbortPacket)) break;
      if (deviceMode != MODE_PAIRING) break;
      if (memcmp(data + 1, pairingMac, 6) != 0) break;

      PairAbortPacket incoming = {};
      memcpy(&incoming, data, sizeof(incoming));

      if(memcmp(incoming.hash, abortValue, 32) == 0){
        
        //send ACK back
        uint8_t ackVal[32];
        computePairAckValue(incoming.hash, ackVal);
        PairAckPacket ack = {};
        ack.type = MSG_PAIR_ACK;
        memcpy(ack.senderId, myDeviceId, 6);
        memcpy(ack.hash, ackVal, 32);
        sendLoRa((uint8_t*)&ack, sizeof(ack));

        int abortType = incoming.abortType; //cancel is defined as 1 and block = 2.

        //if blocked 
        if(abortType == ABORT_BLOCK){
          removeCurrentPair(); //removeCurrentPair does nothing if not alr paired. if paired tho it remove it.
          
          popupText = "BLOCKED";
          popupReturnScreen = SCREEN_DISCOVERY;
          popupColour = TFT_RED;

          updatePopup = true;
        }

        //if user cancelled:
        if(abortType == ABORT_CANCEL){

          popupText = "User cancelled";
          popupReturnScreen = SCREEN_DISCOVERY;
          popupColour = TFT_WHITE;

          updatePopup = true;
        }

        resetPairingState();
        currentScreen = SCREEN_DISCOVERY;
        updateDiscoveryScreen = true;
      }
      
      //shouldnt do anything if its a fake hash so that spoofers cannot cause trouble.
      break;
    }

    case MSG_TEXT: {
      if (len < (int)offsetof(TextPacket, cipherText) || len > (int)sizeof(TextPacket)) break;
      if (deviceMode != MODE_CHATTING) break;
      if (memcmp(data + 1, chatPeerMac, 6) != 0) break;

      TextPacket incoming = {};
      memcpy(&incoming, data, len);

      int cipherLen = len - offsetof(TextPacket, cipherText);
      if(cipherLen <= 0 || cipherLen > 126) break;

      //if our ACK packet is not recvied by the other device but we sent it, the other device will resend the same 
      //message. just resend the ACK packet if so. Not ran through decryptIncomingText so that it's not duped onto text chat.
      if(hasLastAcceptedTag && memcmp(incoming.polyTag, lastAcceptedTag, 16) == 0){
        //computes ACK value for the message using session key
        uint8_t ackValue[32];
        computeAckValue(incoming.polyTag, ackValue);

        AckPacket ack = {};
        ack.type = MSG_ACK;
        memcpy(ack.senderId, myDeviceId, 6);
        memcpy(ack.hash, ackValue, 32);
        sendLoRa((uint8_t*)&ack, sizeof(ack));
        break;
      }

      //this line will run function and also return true or false if it succeeded.
      if(decryptIncomingText(incoming, len)){
        memcpy(lastAcceptedTag, incoming.polyTag, 16);
        hasLastAcceptedTag = true;

        uint8_t ackValue[32];
        computeAckValue(incoming.polyTag, ackValue);

        AckPacket ack = {};
        ack.type = MSG_ACK;
        memcpy(ack.senderId, myDeviceId, 6);
        memcpy(ack.hash, ackValue, 32);
        sendLoRa((uint8_t*)&ack, sizeof(ack));
      }
      break;
    }

    case MSG_ACK: {
      if (len != sizeof(AckPacket)) break;
      if (deviceMode != MODE_CHATTING) break;
      if (memcmp(data + 1, chatPeerMac, 6) != 0) break;

      AckPacket incoming = {};
      memcpy(&incoming, data, sizeof(incoming));

      ///checks if the recieved ack matches the current pending message expected ack.
      if(awaitingAck && memcmp(incoming.hash, pendingExpectedAck, 32) == 0){
        awaitingAck = false;
        if(currentScreen == SCREEN_CHAT) updateChatScreen = true;
      }

      break;
    }
    case MSG_PAIR_ACK: {
      if (len != sizeof(PairAckPacket)) break;
      if (!awaitingPairAck) break;
      PairAckPacket incoming = {};
      memcpy(&incoming, data, sizeof(incoming));
      if(memcmp(incoming.hash, pendingPairExpectedAck, 32) == 0) awaitingPairAck = false;
      break;
    }

    // the else statement:
    default: {
        break;
    }
  }
}

//---- LR32 UART transport functions ---- !!!!!!!!!!!!!!!!  
//DX-LR32 in broadcast mode requires: byte1: target channel. // this is stripped out from recieving side and they only see data after it.
//the code sends len of msg as next byte then actual msg. 

void sendLoRa(const uint8_t* payload, uint8_t len) {
  if (len == 0 || len > MAX_LORA_PACKET) return;
  LoRaSerial.write(LORA_CHANNEL); //send recv channel 1st byte to match LR32 requirements
  LoRaSerial.write(len); //next byte is data len
  LoRaSerial.write(payload, len); //data
}

//we use the len value sent in second byte (we read it as first byte as first byte of channel is stripped on send) to figure out how much to read.
void pollLoRaReceive() {
  if (!LoRaSerial.available()) return;

  uint8_t len = 0;
  LoRaSerial.readBytes(&len, 1);
  if (len == 0 || len > MAX_LORA_PACKET) return; //corrupt/garbage length byte, drop it.

  uint8_t buf[MAX_LORA_PACKET];
  int got = LoRaSerial.readBytes(buf, len);
  if (got != len) return; //timed out / short read, drop it.

  int8_t rssi = 0;
  if (LORA_RSSI_ENABLED) {
    uint8_t rssiByte = 0;
    if (LoRaSerial.readBytes(&rssiByte, 1) == 1) {
      rssi = (int)rssiByte - 255; // DX-LR32 datasheet: actual dBm = -(0xFF - byte). Check your own data sheet if using a different UART module!!!
    }
  }

  processIncomingPacket(buf, len, rssi);
}

void removeStaleDevices(){
  if(millis() - lastRemoveCheck > 10000){
    lastRemoveCheck = millis();

    if(currentScreen == SCREEN_DISCOVERY) updateSignal = true;

    //discoveryList screen only ever adds, thats why even with refreshes every second, we still need to remove devices:
    bool removed = false;

    //checks for all discovered devices if last seen less than 25s ago. Discovery broadcasts every 10s.
    for(int i = 0; i < discoveredCount; i++){
      if(millis() - discoveredDevices[i].lastSeen > 25000){

        //loops through all discovered devices after the to be removed discovered device, and moves them down one.
        for(int j = i; j < discoveredCount - 1; j++){
          discoveredDevices[j] = discoveredDevices[j + 1];
        }
        discoveredCount--;
        i--; // if i = 3 got removed, the previous code moved i = 4 to i = 3, so we recheck it.
        removed = true;
      }
    }

    if(removed){

      //updates the scroll to start at the right place if removing a device caused the list to not be a multiple of 4. PS: device list scroll is only ever 0,4 or 8.
      if(deviceListScroll > 0 && deviceListScroll >= discoveredCount){
      deviceListScroll = max(0, discoveredCount - 4); //checks which is bigger so we dont get a neg value.
    }
    if(currentScreen == SCREEN_DISCOVERY) updateDiscoveryScreen = true;
    }
  }
}

void runProtocolLogic() {

  if(awaitingPairAck && millis() >= pendingPairNextSend){
      if(pendingPairAttempts < MAX_SEND_ATTEMPTS){
        sendLoRa(pendingPairPacket, pendingPairPacketLen);
        pendingPairAttempts++;
        pendingPairNextSend = millis() + 3000 + (esp_random() % 4000);
      } else {
        awaitingPairAck = false;
      }
    }

    switch(deviceMode){
        case MODE_DISCOVERING:{
            removeStaleDevices();

            DiscoveryPacket outgoing = {};
            outgoing.type = MSG_DISCOVERY;
            memcpy(outgoing.senderId, myDeviceId, 6);
            Username.toCharArray(outgoing.username, 16);
            memcpy(outgoing.publicKey, myPublicKey, 32);


            if(millis() >= nextBroadcastTime){
                sendLoRa((uint8_t*)&outgoing, sizeof(outgoing));
                lastBroadcastTime = millis();
                nextBroadcastTime = lastBroadcastTime + 10000 + (esp_random() % 4000); // 10s always + rand 0-4999ms delay
            }
            break;
        }
        case MODE_PENDING:{
          //after 3s if no PairRequestReceived packet (was 500ms under ESP-NOW; a PairRequestPacket
          //round trip over LEVEL2 LoRa takes roughly a second by itself, so give it real margin):
          if(millis() - pendingStartTime > 3000){

            resetPairingState(); //sets MODE back to discovery + clears pairing partner
            popup("No Response", SCREEN_DISCOVERY, TFT_WHITE); // a pop-up says "no response". changes to SCREEN_DISCOVERY after 1 second.
          }
          break; 
        } 
        case MODE_PAIRING: break;
        case MODE_CHATTING: {
          //checks if acknowledgement packet has been recv and if not, it loops.
          if(awaitingAck && millis() - pendingLastSendTime > pendingRetryDelay){
            
            //resends packet if max send attempts hasn't been exceeded
            if(pendingAttempts < MAX_SEND_ATTEMPTS){
              sendLoRa((uint8_t*)&pendingPacket, pendingPacketLen);
              pendingAttempts++;
              pendingLastSendTime = millis();
              pendingRetryDelay = ACK_TIMEOUT + (esp_random() % ACK_JITTER_MAX);
              
              //updates screen so that "sending..." can be drawn
              if(currentScreen == SCREEN_CHAT && pendingAttempts == 2) updateChatScreen = true;
            }
            //sends back to discovery screen if other user fails to send ack packet after multiple attempts.
            else{
              awaitingAck = false;
              deviceMode = MODE_DISCOVERING;
              popup("Connection Lost", SCREEN_DISCOVERY, TFT_RED);
            }
          }
        break;
      }
    }
}

//checks if LoRa module is in "AT" mode, resets on esp32 doesnt always mean the uart resets too. Cannot transmit/recv in AT mode so we check on boot.
bool loraInATMode() {
  while (LoRaSerial.available()) LoRaSerial.read(); // clear any trash bytes first

  delay(50);
  LoRaSerial.print("AT\r\n");

  unsigned long start = millis();
  String resp = "";
  while (millis() - start < 200) {
    while (LoRaSerial.available()) resp += (char)LoRaSerial.read();
    if (resp.indexOf("OK") != -1) return true;
  }
  return false;
}
//just unsticks us from AT mode if still in it. 
void exitATModeIfStuck() {
  if (loraInATMode()) {
    delay(50);
    LoRaSerial.print("+++\r\n");
    delay(50);
  }
}
bool isBlocked(const uint8_t* mac, const char* username, const uint8_t* publicKey){
  for(int i = 0; i < blockedCount; i++){
    if(memcmp(blockedDevices[i].mac, mac, 6) == 0 && strcmp(blockedDevices[i].username, username) == 0 && memcmp(blockedDevices[i].publicKey, publicKey, 32) == 0) return true;
  }
  return false;
}

bool isPaired(const uint8_t* mac, const char* username, const uint8_t* publicKey){
  for(int i = 0; i < pairedCount; i++){
    if(memcmp(pairedDevices[i].mac, mac, 6) == 0 && strcmp(pairedDevices[i].username, username) == 0 && memcmp(pairedDevices[i].publicKey, publicKey, 32) == 0) return true;
  }
  return false;
}

int userColour(const uint8_t* publicKey){
  //sums the value of a users public key and gets a range from 0-20 for one of 20 username colours.
  uint8_t sum = 0;

  for(int i = 0; i < 32; i++){
    sum+=publicKey[i];
  }


  return userColours[sum % 18];
}

// text screen stuff:

// how many lines of "username: text" used up for message i
int chatLineCount(int i){
  //gets whos currently speaking in char array format for the "name: " later.
  const char* name = chatHistory[i].fromMe ? Username.c_str() : chatPeerUsername; 

  //"name: " + text length
  int len = strlen(name) + 2 + strlen(chatHistory[i].text); 

  //returns how many lines required for this text. (min is 1 line)
  return max(1, (len + CHAT_CHARS_PER_LINE - 1) / CHAT_CHARS_PER_LINE); 
}

//calculates where the page text will end at when you give it a starting place.
//chatScroll is what holds the new starting index later on. 
int chatPageEnd(int startingIndex){
  int linesTotal = 0;
  int i = startingIndex;

  while(i < messageCount){
    //calculates the lines of the message 
    int msgLines = chatLineCount(i);

    //if the previous lines + the new lines excedes the max lines we break
    if(linesTotal + msgLines > CHAT_LINES_PER_PAGE) break;

    //otherwise we add the text to (int) lines
    linesTotal += msgLines;
    //moves to the next text index.
    i++;
  }

  //in the case text exceeds page length somehow (not currently possible due to 125 char count but just insurance) it should return the next line to not cause chatShowLatestPage() to infinitely loop.
  if(i == startingIndex && startingIndex < messageCount) i = startingIndex + 1;
  
  //returns what index chat page ends at.
  return i;
}

void chatShowLatestPage(){
  int s = 0;

  //starts at index == 0 of chatHistory and keeps looping until it finds the page with the index less than the message count. 
  while(chatPageEnd(s) < messageCount){
    s = chatPageEnd(s);
  }

  //returns chatScroll which is where the page should start. 
  chatScroll = s;
}

//same as chatShowLatestPage() but returns page b4 newest page.
int chatPrevPageStart(int prevIndex){
  int i = 0;
  int prev = 0;

  //rechecks from index == 0 and loops all the way to the current page. 
  while(i < prevIndex){
    prev = i;
    i = chatPageEnd(i);
  }

  //returns value of the page just before the current one.
  return prev;
}


//encryption

void sendEncryptedText(const char* text){
  if(awaitingAck) return; //one message at a time is checked for being received. 

  if(messageCount >= MAX_MESSAGES){
    resetPairingState();
    popup("MAX MESSAGES", SCREEN_DISCOVERY, TFT_RED);
    return;
  }

  strcpy(chatHistory[messageCount].text, text);
  chatHistory[messageCount].fromMe = true;
  messageCount++;

  TextPacket outgoing = {};
  outgoing.type = MSG_TEXT;
  memcpy(outgoing.senderId, myDeviceId, 6);

  for(int i = 0; i < 12; i++) outgoing.encryptSalt[i] = esp_random() & 0xFF;

  int textLen = strlen(text) + 1; // includes null terminator

  chacha.setKey(sessionKey, 32);
  chacha.setIV(outgoing.encryptSalt, 12);
  chacha.encrypt(outgoing.cipherText, (const uint8_t*)text, textLen);
  chacha.computeTag(outgoing.polyTag, 16);

  computeAckValue(outgoing.polyTag, pendingExpectedAck);

  int packetLen = offsetof(TextPacket, cipherText) + textLen;

  memcpy(&pendingPacket, &outgoing, sizeof(pendingPacket)); // saved for retransmit
  pendingPacketLen = packetLen;
  pendingAttempts = 1;
  pendingLastSendTime = millis();
  pendingRetryDelay = ACK_TIMEOUT + (esp_random() % ACK_JITTER_MAX);
  awaitingAck = true;
  
  sendLoRa((uint8_t*)&outgoing, offsetof(TextPacket, cipherText) + textLen);

  chatShowLatestPage(); // jump to newest page
  updateChatScreen = true;
}

bool decryptIncomingText(TextPacket &incoming, int len){
  if(messageCount >= MAX_MESSAGES){
    resetPairingState();
    popupText = "MAX MESSAGES";
    popupReturnScreen = SCREEN_DISCOVERY;
    popupColour = TFT_RED;
    updatePopup = true;
    return false;
  }

  int cipherLen = len - offsetof(TextPacket, cipherText);
  if(cipherLen <= 0 || cipherLen > 126) return false; // out of range, must be a bad packet.

  char decryptRecv[126] = {};

  chacha.setKey(sessionKey, 32);
  chacha.setIV(incoming.encryptSalt, 12);
  chacha.decrypt((uint8_t*)decryptRecv, incoming.cipherText, cipherLen);

  if(chacha.checkTag(incoming.polyTag, 16)){
    strcpy(chatHistory[messageCount].text, decryptRecv);
    chatHistory[messageCount].fromMe = false;
    messageCount++;

    chatShowLatestPage();
    if(currentScreen == SCREEN_CHAT) updateChatScreen = true;
    return true;
  }

  //if spoofed device copying MAC of peer device tries to send bogus text we should just ignore it.
  return false;
}

//ACK value is derived from session key + polyTag + "received_message" hashed. Using shared secret for ACK values means that it can't be spoofed
void computeAckValue(const uint8_t* polyTag, uint8_t* outputHash){
  hasher.reset();
  hasher.update(sessionKey, 32);
  hasher.update(polyTag, 16);
  hasher.update((const uint8_t*)"received_message", 17);
  hasher.finalize(outputHash, 32);
}

void computePairAckValue(const uint8_t* value32, uint8_t* outHash){
  hasher.reset();
  hasher.update(sessionKey, 32);
  hasher.update(value32, 32);
  hasher.update((const uint8_t*)"pair_ack", 8);
  hasher.finalize(outHash, 32);
}

// use instead of a bare sendLoRa() for Confirm/Abort
void sendPairPacketReliable(const uint8_t* packet, uint8_t len, const uint8_t* ackSourceValue){
  memcpy(pendingPairPacket, packet, len);
  pendingPairPacketLen = len;
  computePairAckValue(ackSourceValue, pendingPairExpectedAck);
  pendingPairAttempts = 1;
  pendingPairNextSend = millis() + 3000 + (esp_random() % 4000); // random element so that repeats don't collide
  awaitingPairAck = true;
  sendLoRa(packet, len);
}

// pairing functions
void derivePairingHashes(){
  //checks if device is reconnecting or new.
  if(isPaired(pairingMac, pairingUsername, pairingPublicKey) == true && theirReconnection == true) isReconnecting = true;

  // clears pair in the case of you being paired but other device unpaired you.
  if(isReconnecting == false && isPaired(pairingMac, pairingUsername, pairingPublicKey) == true) removeCurrentPair();

  uint8_t privKeyScratch[32];
  memcpy(privKeyScratch, myPrivateKey, 32); // read below (this is actually just safety, only below matters.)

  uint8_t sharedSecret[32];
  memcpy(sharedSecret, pairingPublicKey, 32); // dh2 function overwrites left variable, temp file ensures their public key isnt lost.

  Curve25519::dh2(sharedSecret, privKeyScratch); // sharedSecret overwritten by session key. Order doesnt matter, will return same answer regardless.

  uint8_t orderedFirst[16]; //unlike sharedSecret, which returns same ans regardless of order, rand numbers wont, so we need to order them.
  uint8_t orderedSecond[16];

  if(memcmp(myRandNum, theirRandNum, 16) > 0){
    memcpy(orderedFirst, myRandNum, 16);
    memcpy(orderedSecond, theirRandNum, 16);
  } else {
    memcpy(orderedFirst, theirRandNum, 16);
    memcpy(orderedSecond, myRandNum, 16);
  }

  //pair codes hashing. no need for pairing codes if alr paired.
  if(isReconnecting == false){
    uint8_t codeHash[32];
    hasher.reset(); //clearing hasher
    hasher.update(sharedSecret, 32);
    hasher.update(orderedFirst, 16);
    hasher.update(orderedSecond, 16);
    hasher.update((const uint8_t*)"pairing_code", 12);
    hasher.finalize(codeHash, 32); //returns hash to codeHash.

    //where code will stored as a value not an array.
    uint32_t codeValue; 

    memcpy(&codeValue, codeHash, 4);
    uint32_t code = codeValue % 1000000; //puts code in a format easy to turn into a 6 digit pair code

    //now in 6 digit format. function just lets you save things as strings the same way you would do for printf. done so i can do tft.print() once instead of 6 times.
    snprintf(pairingCodeStr, sizeof(pairingCodeStr), "%03lu %03lu", code / 1000, code % 1000); //saved in global variable.
  }

  //session key hashing:
  hasher.reset();
  hasher.update(sharedSecret, 32);
  hasher.update(orderedSecond, 16);
  hasher.update(orderedFirst, 16);
  hasher.update((const uint8_t*)"session_key", 11);
  hasher.finalize(sessionKey, 32); //saved in global variable

  //abortValue hash:
  hasher.reset();
  hasher.update(orderedSecond, 16);
  hasher.update(orderedFirst, 16);
  hasher.update(sharedSecret, 32);
  hasher.update((const uint8_t*)"abort", 5);
  hasher.finalize(abortValue, 32); //saved in global variable

  // finally, the actual confirm value. 
  hasher.reset();
  hasher.update(orderedFirst, 16);
  hasher.update(sharedSecret, 32);
  hasher.update(orderedSecond, 16);
  hasher.update((const uint8_t*)"confirm", 7);
  hasher.finalize(confirmValue, 32); //saved in a global variable.

}

void resetPairingState(){

  memset(pairingMac, 0, 6);
  memset(pairingUsername, 0, 16);
  memset(pairingPublicKey, 0, 32);
  memset(theirRandNum, 0 , 16);
  memset(myRandNum, 0, 16);
  memset(sessionKey, 0 ,32);
  
  
  deviceMode = MODE_DISCOVERING;
  currentScreen = SCREEN_DISCOVERY;

  sentOwnConfirm = false;
  peerConfirmRecieved = false;
  isReconnecting = false;
  theirReconnection = false;
}

void tryPairing(){
  if(!sentOwnConfirm || !peerConfirmRecieved) return;
  
  //compare hashes!!
  if(memcmp(peerConfirmHash, confirmValue, 32) == 0){
    // hashes match. pair succeded. 

    //makes sure we havent alr paired.
    if(pairedCount < MAX_PAIRED && !isPaired(pairingMac, pairingUsername, pairingPublicKey)){
      memcpy(pairedDevices[pairedCount].mac, pairingMac, 6);
      memcpy(pairedDevices[pairedCount].username, pairingUsername, 16);
      memcpy(pairedDevices[pairedCount].publicKey, pairingPublicKey, 32);
      pairedCount++;

      savePairedDevices(); //updates flash mem to new paired devices.

    }

    if(isPaired(pairingMac, pairingUsername, pairingPublicKey)) {
      memcpy(chatPeerMac, pairingMac, 6);
      memcpy(chatPeerUsername, pairingUsername, 16);
      memcpy(chatPeerPublicKey, pairingPublicKey, 32);

      messageCount = 0;
      chatScroll = 0;

      resetPairingState();
      deviceMode = MODE_CHATTING;
    
      popupText = "Connected!"; 
      popupReturnScreen = SCREEN_CHAT; 
      popupColour = TFT_GREEN;

      updatePopup = true;
      
    }

    else{
      resetPairingState();
      popupText = "MAX PAIRED DEVICES"; 
      popupReturnScreen = SCREEN_DISCOVERY; 
      popupColour = TFT_ORANGE;

      updatePopup = true;
      currentScreen = SCREEN_DISCOVERY;
      updateDiscoveryScreen = true;
    }
  }

  //in the case of hash not matching, DO NOTHING!!!!
  //prevents spoofed Denial of serive.
  else{}

}

void removeCurrentPair(){
  //removing the blocked device from discovery screen by finding it.
  for(int i = 0; i < pairedCount; i++){
          
    if(memcmp(pairingMac, pairedDevices[i].mac, 6) == 0 && strcmp(pairingUsername, pairedDevices[i].username) == 0 && memcmp(pairingPublicKey, pairedDevices[i].publicKey, 32) == 0){ //if the mac of pairing mac matches discoveredDevices[i].mac, we found them.

      for(int j = i; j < pairedCount - 1; j++){//moves all devices after removed device back one.
        pairedDevices[j] = pairedDevices[j + 1];
      }
      pairedCount--;
      savePairedDevices();

      break; // escapes int i for loop since we alr found the device.
    }
  }
}

//boot functions:
void bootSequence(){
  pref.begin("Main", false);
  Username = pref.getString("username", "N/A");
  pref.end();

  if(Username == "N/A"){ //if username not found it must be first boot. run will keep being menu until username given
    currentScreen = SCREEN_USERNAME_INIT;
    drawScreen(currentScreen);
  }
  else{
    pref.begin("Main", false);
    size_t len = pref.getBytes("public_Key", myPublicKey, 32);
    pref.getBytes("private_Key", myPrivateKey, 32);
    pref.end();

    if(len != 32) ESP.restart();

    currentScreen = SCREEN_DISCOVERY;
    deviceMode = MODE_DISCOVERING;
    drawScreen(currentScreen);
  }
}

void finishFirstBoot(){

  //reset screen:
  tft.fillScreen(TFT_BLACK);
  tft.drawRect(0 + 2, 0 + 2, 320 - 2 - 2, 240 - 2 - 2, TFT_WHITE);

  tft.setCursor(160 - ((12* 6 * 2)/2), 112);
  tft.print("Resetting...");

  Username = String(typedText);

  pref.begin("Main", false);
  pref.putString("username", Username);

  Curve25519::dh1(myPublicKey, myPrivateKey);
  pref.putBytes("public_Key", myPublicKey, 32);
  pref.putBytes("private_Key", myPrivateKey, 32);
  pref.end();

  if(loraInATMode() == false){
    delay(100);
    LoRaSerial.print("+++\r\n");
    delay(100);
  }
  LoRaSerial.print("AT+LEVEL2\r\n");
  delay(100);
  LoRaSerial.print("AT+MODE2\r\n");
  delay(100);
  LoRaSerial.print("AT+CHANNEL12\r\n");
  delay(100);
  LoRaSerial.print("AT+DRSSI1\r\n");
  delay(100);
  LoRaSerial.print("AT+POWE14\r\n");
  delay(100);
  LoRaSerial.print("+++\r\n");
  delay(200);

  ESP.restart();
}

void bootScreen(){
  pref.begin("Main", false);
  String storedUsername = pref.getString("username", "N/A");
  pref.end();

  tft.fillScreen(TFT_BLACK);
  tft.drawRect(0 + 2, 0 + 2, 320 - 2 - 2, 240 - 2 - 2, TFT_WHITE);
  tft.setTextSize(2);

  if(storedUsername == "N/A"){
    const char* line1 = "Welcome to";
    const char* line2 = "ESP-Encrypt";

    tft.setCursor(160 - (strlen(line1) * 6 * 2)/2, 100);
    tft.print(line1);

    tft.setCursor(160 - (strlen(line2) * 6 * 2)/2, 130);
    tft.print(line2);
  }
  else{
    const char* line1 = "Welcome back,";

    tft.setCursor(160 - (strlen(line1) * 6 * 2)/2, 100);
    tft.print(line1);

    tft.setCursor(160 - (storedUsername.length() * 6 * 2)/2, 130);
    tft.print(storedUsername);
  }

  delay(1000);
  exitATModeIfStuck();
  delay(1000);
}

void savePairedDevices(){
  pref.begin("Peers", false);
  pref.putBytes("paired", pairedDevices, sizeof(pairedDevices));
  pref.putInt("pairedCount", pairedCount);
  pref.end();
}

void loadPairedDevices(){
  pref.begin("Peers", false);
  pref.getBytes("paired", pairedDevices, sizeof(pairedDevices));
  pairedCount = pref.getInt("pairedCount", 0);
  pref.end();
}

void saveBlockedDevices(){
  pref.begin("Adversaries", false);
  pref.putBytes("blocked", blockedDevices, sizeof(blockedDevices));
  pref.putInt("blockedCount", blockedCount);
  pref.end();
}

void loadBlockedDevices(){
  pref.begin("Adversaries", false);
  pref.getBytes("blocked", blockedDevices, sizeof(blockedDevices));
  blockedCount = pref.getInt("blockedCount", 0);
  pref.end();
}


//draw functions

void usernameInitPage(){
  tft.fillScreen(TFT_BLACK);
  tft.drawRect(0 + 2, 0 + 2, 320 - 2 - 2, 240 - 2 - 2, TFT_WHITE);

  tft.setCursor(61 ,20);
  tft.setTextSize(3);
  tft.print("ESP_Encrypt");

  tft.setTextSize(2);
  tft.setCursor(61 - 48, 86);
  tft.print("Welcome to the first boot\n");

  tft.setCursor(58, 132);
  tft.print("Choose a username:");

  tft.drawRect(52, 162, 216, 16 + 10, TFT_WHITE);

  if(typedIndex > 0){
    tft.fillRect(273, 162 - 3, 40, 26 + 6, TFT_GREEN);
    tft.drawRect(273, 162 - 3, 40, 26 + 6, TFT_WHITE);
    tft.drawChar(287, 167, '>', TFT_WHITE, TFT_GREEN, 2);

    tft.setCursor(160 - ((12*typedIndex)/2), 167);
    tft.print(typedText);
  }

  tft.setTextSize(1);
  tft.setTextColor(TFT_ORANGE);
  tft.setCursor(52, 162 + 26 + 15);
  tft.print("NOTE: You will need to factory reset\n");
  tft.setCursor(88, 172 + 26 + 15);
  tft.print("if you change your mind.");

  tft.setTextColor(TFT_WHITE);
  tft.setTextSize(2);
}

void drawSignal(DeviceListConfig &cfg){
  for(int i = 0; i < 4; i++){
    int deviceIndex = *cfg.scroll + i;
    if(deviceIndex >= *cfg.count) break;

    int rowY = 30 + (i * 45);

    //draw signal bars
    int strength = 0;

    if(cfg.devices[deviceIndex].rssi >= -50) strength = 4;
    else if(cfg.devices[deviceIndex].rssi >= -60) strength = 3;
    else if(cfg.devices[deviceIndex].rssi >= -70) strength = 2;
    else strength = 1;

    int bottomMaxBarY = rowY + 22 + 10;

    tft.fillRect(275, bottomMaxBarY - 5, 5, 5, TFT_GREEN); //first bar, always green. //weakest
    tft.drawRect(275, bottomMaxBarY - 5, 5, 5, TFT_DARKGREEN);


    tft.fillRect(285, bottomMaxBarY - 10, 5, 10, strength >= 2 ? TFT_GREEN : TFT_LIGHTGREY); //second bar.
    tft.drawRect(285, bottomMaxBarY - 10, 5, 10, strength >= 2 ? TFT_DARKGREEN : TFT_DARKGREY);

  
    tft.fillRect(295, bottomMaxBarY - 15, 5, 15, strength >= 3 ? TFT_GREEN : TFT_LIGHTGREY); //third bar.
    tft.drawRect(295, bottomMaxBarY - 15, 5, 15, strength >= 3 ? TFT_DARKGREEN : TFT_DARKGREY);

  
    tft.fillRect(305, bottomMaxBarY - 20, 5, 20, strength == 4 ? TFT_GREEN : TFT_LIGHTGREY); //top bar. // the strongest
    tft.drawRect(305, bottomMaxBarY - 20, 5, 20, strength == 4 ? TFT_DARKGREEN : TFT_DARKGREY);
  }
}

void drawGenericDeviceList(DeviceListConfig &cfg){
  //clears screen
  tft.fillScreen(TFT_BLACK);

  // will return a true or false value
  rightArrowActive = (*cfg.scroll + 4 < *cfg.count); 
  leftArrowActive  = (*cfg.scroll > 0);
  
  //draw border
  tft.drawRect(2, 30, 316, 180, cfg.colour);

  //draw username at bottom middle
  tft.setTextColor(userColour(myPublicKey));
  tft.setCursor(160 - (Username.length() * 6 * 2)/2, 217);
  tft.print(Username);

  //draw left arrow
  if(leftArrowActive == true){
    tft.drawRect(2, 210, 60, 30, cfg.colour);
    tft.drawChar(25, 217, '<', cfg.colour, TFT_BLACK, 2);
  }

  //draw right arrow
  if(rightArrowActive == true){
    tft.drawRect(258, 210, 60, 30, cfg.colour);
    tft.drawChar(282, 217, '>', cfg.colour, TFT_BLACK, 2);
  }

  // draw top left button
  tft.drawRect(2, 2, 60, 30, cfg.colour);
  tft.drawChar(25, 9, cfg.cornerSymbol, cfg.colour, TFT_BLACK, 2);

  //title header
  tft.setTextSize(2);
  tft.setCursor(160 - ((strlen(cfg.title) * 6 * 2)/2), 7);
  tft.setTextColor(cfg.colour);
  tft.print(cfg.title);

  for (int i = 0; i < 4; i++) {
    int deviceIndex = *cfg.scroll + i;
    if (deviceIndex >= *cfg.count) break;   // fewer than 4 devices on this page

    int rowY = 30 + (i * 45);
    tft.drawRect(2, rowY, 316, 45, cfg.colour);
    tft.setCursor(10, rowY + 14);
    tft.setTextColor(userColour(cfg.devices[deviceIndex].publicKey));
    tft.print(cfg.devices[deviceIndex].username);

    //if we are drawing the discovery list:
    if(cfg.isDiscoveryList == true){
      
      //draw pairing circle
      int circleColour = isPaired(cfg.devices[deviceIndex].mac, cfg.devices[deviceIndex].username, cfg.devices[deviceIndex].publicKey) ? TFT_GREEN : TFT_LIGHTGREY; //makes the pairing circle green if paired and grey if unpaired.
      tft.fillCircle(250, rowY + 22, 5, circleColour);
      

      //draw signal bars
      int strength = 0;

      if(cfg.devices[deviceIndex].rssi >= -50) strength = 4;
      else if(cfg.devices[deviceIndex].rssi >= -60) strength = 3;
      else if(cfg.devices[deviceIndex].rssi >= -70) strength = 2;
      else strength = 1;

      int bottomMaxBarY = rowY + 22 + 10;

      tft.fillRect(275, bottomMaxBarY - 5, 5, 5, TFT_GREEN); //first bar, always green. //weakest
      tft.drawRect(275, bottomMaxBarY - 5, 5, 5, TFT_DARKGREEN);


      tft.fillRect(285, bottomMaxBarY - 10, 5, 10, strength >= 2 ? TFT_GREEN : TFT_LIGHTGREY); //second bar.
      tft.drawRect(285, bottomMaxBarY - 10, 5, 10, strength >= 2 ? TFT_DARKGREEN : TFT_DARKGREY);

  
      tft.fillRect(295, bottomMaxBarY - 15, 5, 15, strength >= 3 ? TFT_GREEN : TFT_LIGHTGREY); //third bar.
      tft.drawRect(295, bottomMaxBarY - 15, 5, 15, strength >= 3 ? TFT_DARKGREEN : TFT_DARKGREY);

  
      tft.fillRect(305, bottomMaxBarY - 20, 5, 20, strength == 4 ? TFT_GREEN : TFT_LIGHTGREY); //top bar. // the strongest (of today)
      tft.drawRect(305, bottomMaxBarY - 20, 5, 20, strength == 4 ? TFT_DARKGREEN : TFT_DARKGREY);

    }
    //in the case of paired or blocked devices:
    else{
      tft.setTextColor(TFT_RED);
      tft.setCursor(295, rowY + 14);
      tft.print("X");
    }
  }
  
  //return to normal
  tft.setTextColor(TFT_WHITE);
  tft.setTextSize(2);
}

void drawSettings(){
  //clear screen
  tft.fillScreen(TFT_BLACK);

  //Settings title
  tft.setCursor(106, 7);
  tft.setTextSize(2);
  tft.print("Settings:");
  

  //draw 3 rows of settings, Blocked devices, Paired Devices, Factory Reset.
  tft.setTextSize(3);

  //Paired Devices: 
  tft.drawRect(2, 37, 316, 53, TFT_WHITE);
  tft.setTextColor(TFT_GREEN);
  tft.setCursor(12, 37 + 14);
  tft.print("Paired devices");

  tft.setCursor(298, 37 + 14);
  tft.print(">");

  //Blocked devices:
  tft.drawRect(2, 102, 316, 53, TFT_WHITE);
  tft.setTextColor(TFT_ORANGE);
  tft.setCursor(12, 102 + 14);
  tft.print("Blocked devices");
  
  tft.setCursor(298, 102 + 14);
  tft.print(">");

  //Factory Reset:
  tft.drawRect(2, 167, 316, 53, TFT_WHITE);
  tft.setTextColor(TFT_RED);
  tft.setCursor(12, 167 + 14);
  tft.print("Factory reset");

  tft.setCursor(298, 167 + 14);
  tft.print(">");

  tft.setTextSize(2);

  //draw back button
  tft.drawRect(2, 2, 60, 30, TFT_WHITE);
  tft.drawChar(25, 9, '<', TFT_WHITE, TFT_BLACK, 2);

  tft.setTextColor(TFT_WHITE);
}

void drawFactoryReset(){
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);

  //draw white border
  tft.drawRect(2, 30, 316, 210, TFT_WHITE);

  //header
  tft.setCursor(75, 7);
  tft.setTextColor(TFT_RED);
  tft.print("Factory reset:");
  tft.setTextColor(TFT_WHITE);

  //draw back button
  tft.drawRect(2, 2, 60, 30, TFT_WHITE);
  tft.drawChar(25, 9, '<', TFT_WHITE, TFT_BLACK, 2);

  // draw reset button
  tft.drawRect(258, 0, 60, 30, TFT_RED);
  tft.drawChar(282, 7, '!', TFT_RED, TFT_BLACK, 2);

  //text
  tft.setCursor(159 - ((sizeof("Are you sure?")-1) * 12)/2, 35); 
  tft.print("Are you sure?");

  tft.setCursor(159 - ((sizeof("Saved pairs will be lost,")-1) * 12)/2, 75); 
  tft.print("Saved pairs will be lost,");

  tft.setCursor(159 - ((sizeof("Username will be reset,")-1) * 12)/2, 95); 
  tft.print("username will be reset,");
            
  tft.setCursor(159 - ((sizeof("Encryption keys will be")-1) * 12)/2, 115); 
  tft.print("Encryption keys will be");

  tft.setCursor(159 - ((sizeof("reset.")-1) * 12)/2, 135); 
  tft.print("reset.");


  tft.setCursor(159 - ((sizeof("Press the '!' key at the")-1) * 12)/2, 178); 
  tft.print("Press the '!' key at the");

  tft.setCursor(159 - ((sizeof("top right to reset.")-1) * 12)/2, 198); 
  tft.print("top right to reset.");

}

void drawPairScreen(){
  tft.fillScreen(TFT_BLACK);
  tft.setTextSize(2);
  
  //draw white border
  tft.drawRect(2, 2, 316, 236, TFT_WHITE);

  //draw username at top middle.
  tft.setTextSize(3);
  tft.setCursor(160 - (strlen(pairingUsername) * 6 * 3)/2, 10);
  tft.print(pairingUsername);
  tft.setTextSize(2);
 
  //draw different things depending on reconnection or new pair request.
  if(isReconnecting == false){

    //"wants to pair."
    tft.setCursor(160 - (strlen("wants to pair.") * 6 * 2)/2, 40);
    tft.print("wants to pair.");

    //"Compare onscreen codes:"
    tft.setCursor(160 - (strlen("Compare onscreen codes:") * 6 * 2)/2, 60);
    tft.print("Compare onscreen codes:");

    //pairing codes
    tft.setTextSize(5);

    //draw underscores below numbers
    tft.setCursor(160 - 105, 99);
    tft.setTextColor(TFT_DARKGREY);
    tft.print("___ ___");

    //draw actual passcode
    tft.setCursor(160 - 105, 89);
    tft.setTextColor(TFT_LIGHTGREY);
    tft.print(pairingCodeStr);
    tft.setTextSize(2);

    //pair
    tft.drawRect(165, 142, 120, 30, TFT_WHITE);
    tft.setCursor(201, 149);
    tft.setTextColor(TFT_GREEN);
    if(sentOwnConfirm == false) tft.print("Pair");

    //block 
    tft.drawRect(100, 182, 120, 30, TFT_WHITE);
    tft.setCursor(130, 189);
    tft.setTextColor(TFT_RED);
    tft.print("Block");

    //block note
    tft.setTextSize(1);
    tft.setTextColor(TFT_ORANGE);

    tft.setCursor(160 - 6*strlen("Note: Blocked devices will no longer pop-up.")/2, 217);
    tft.print("Note: Blocked devices will no longer pop-up.");

    tft.setCursor(160 - 6*strlen("You can un-block devices in settings.")/2, 225);
    tft.print("You can un-block devices in settings.");
    tft.setTextSize(2);
  }

  else{
    //"wants to reconnect"
    tft.setCursor(160 - (strlen("wants to reconnect.") * 6 * 2)/2, 40);
    tft.print("wants to reconnect.");

    //reconnect button
    tft.drawRect(165, 142, 120, 30, TFT_WHITE);
    tft.setCursor(171, 149);
    tft.setTextColor(TFT_GREEN);
    if(sentOwnConfirm == false) tft.print("Reconnect");

    //block note
    tft.setTextSize(1);
    tft.setTextColor(TFT_ORANGE);

    tft.setCursor(160 - 6*strlen("Note: This is a paired device.")/2, 217);
    tft.print("Note: This is a paired device.");

    tft.setCursor(160 - 6*strlen("You can un-pair with devices in settings.")/2, 225);
    tft.print("You can un-pair with devices in settings.");
    tft.setTextSize(2);
  }

  //cancel button. (happens for both isReconnecting && !isReconnecting).
  tft.drawRect(30, 142, 120, 30, TFT_WHITE);
  tft.setCursor(54, 149);
  tft.setTextColor(TFT_DARKGREY);
  tft.print("Cancel");

  tft.setTextColor(TFT_WHITE);
  tft.setTextSize(2);

}

void drawTextChat(){
  tft.fillScreen(TFT_BLACK);

  //draws border
  tft.drawRect(2, 30, 316, 150, TFT_WHITE);

  //draws username @ bottom middle
  tft.setTextColor(userColour(myPublicKey));
  tft.setCursor(160 - (Username.length() * 6 * 2)/2, 217);
  tft.print(Username);

  int start = chatScroll;
  int end = chatPageEnd(chatScroll);
  
  //chat page only == 0 when on first page.
  leftArrowActive = (chatScroll > 0);

  rightArrowActive = (end < messageCount);

  //left right arrow conditions
  if(leftArrowActive){
    tft.drawRect(2, 210, 60, 30, TFT_WHITE);
    tft.drawChar(25, 217, '<', TFT_WHITE, TFT_BLACK, 2);
  }
  if(rightArrowActive){
    tft.drawRect(258, 210, 60, 30, TFT_WHITE);
    tft.drawChar(282, 217, '>', TFT_WHITE, TFT_BLACK, 2);
  }

  if(awaitingAck && pendingAttempts > 1){
  //draws "sending..." if waiting on response
  tft.setTextSize(1);
  tft.setTextColor(TFT_YELLOW);
  tft.setCursor(258, 212);
  tft.print("sending...");
  tft.setTextColor(TFT_WHITE);
  tft.setTextSize(2);
  } 

  //text border
  tft.fillRect(2, 180, 256, 30, TFT_BLACK);
  tft.drawRect(2, 180, 256, 30, TFT_WHITE);
  tft.drawRect(3, 181, 254, 28, TFT_WHITE);

  //send key
  tft.fillRect(258, 180, 60, 30, TFT_GREEN);
  tft.drawRect(258, 180, 60, 30, TFT_WHITE);
  tft.drawRect(259, 181, 58, 28, TFT_WHITE);
  tft.drawChar(282, 187, '>', TFT_WHITE, TFT_GREEN, 2);

  //x button top left
  tft.drawRect(2, 2, 60, 30, TFT_WHITE);
  tft.drawChar(25, 9, 'X', TFT_RED, TFT_BLACK, 2);

  //draws username of the chatting peer at top middle.
  tft.setTextSize(2);
  tft.setCursor(160 - strlen(chatPeerUsername)*6*2/2, 7);
  tft.setTextColor(userColour(chatPeerPublicKey));
  tft.print(chatPeerUsername);
  tft.setTextColor(TFT_WHITE);

  //if anything is written, display it in writing box.
  if(typedIndex > 0){
    tft.setViewport(6, 186, 250, 16);
    tft.setCursor(0,0);
    tft.print(typedText);
    tft.resetViewport();
  }

  tft.setViewport(8, 36, 310, 144);
  tft.setCursor(0,0);
  tft.setTextSize(2);

  //draws from start to end index (initialsied at top depending on what page user has put us in) and draws the username and user colour.
  for(int i = start; i < end; i++){
    if(chatHistory[i].fromMe){
      tft.setTextColor(userColour(myPublicKey));
      tft.print(Username);
    } else {
      tft.setTextColor(userColour(chatPeerPublicKey));
      tft.print(chatPeerUsername);
    }
    tft.print(": ");
    tft.setTextColor(TFT_WHITE);
    tft.println(chatHistory[i].text);
  }

  tft.resetViewport();
}

//touch functions

bool updateKeyboard(){

    if (TS.touched() && (millis() - lastTouchTime) > 150 && currentScreen == SCREEN_KEYBOARD) {
    lastTouchTime = millis();
    TS_Point cood = TS.getPoint();
    int screenX = constrain(map(cood.x, 260, 3800, 0, 320), 0, 320);
    int screenY = constrain(map(cood.y, 320, 3800, 0, 240), 0, 240);

    if (screenY >= startY) {
      int row = (screenY - startY) / keyH;

      if(row == 0 && screenX >= row0offset){

        int col = (screenX - row0offset) / keyW;

        if (col >= 0 && col < 12) {
          if (col > 10) col = 10;

          uint8_t action = rowPointer[row][col].action;

          if (action == KB && typedIndex < maxChars) {
            char pressed = shiftOn ? toupper(rowPointer[row][col].label) : rowPointer[row][col].label;

            typedText[typedIndex] = pressed;
            typedIndex++;
            typedText[typedIndex] = '\0';
        
            charsDisplayed();
          }

          if (action == KB_BACKSPACE) {
            if (typedIndex > 0) {
              typedIndex--;
              typedText[typedIndex] = '\0';

              charsDisplayed();
            }
          }
        }
      }

      if(row == 1 && screenX >= row1offset){

        int col = (screenX - row1offset) / keyW;

        if (col >= 0 && col < 11){
          if(col == 10) col = 9;

          uint8_t action = rowPointer[row][col].action;

          if (action == KB && typedIndex < maxChars) {
            char pressed = shiftOn ? toupper(rowPointer[row][col].label) : rowPointer[row][col].label;

            typedText[typedIndex] = pressed;
            typedIndex++;
            typedText[typedIndex] = '\0';

            charsDisplayed();
          }

          if (action == KB_ENTER){
            return true;
          }
        }
      }

      if(row == 2 && screenX >= row2offset){
        int col;

        if((screenX-row2offset)/26 == 1 || (screenX-row2offset)/26 == 0) col = 0;
        else col = (screenX - row2offset - keyW)/keyW;

        if (col >= 0 && col < 12){
            if(col > 8) col = 8;

            uint8_t action = rowPointer[row][col].action;

            if (action == KB && typedIndex < maxChars) {
              char pressed = shiftOn ? toupper(rowPointer[row][col].label) : rowPointer[row][col].label;

              typedText[typedIndex] = pressed;
              typedIndex++;
              typedText[typedIndex] = '\0';

              charsDisplayed();
            }

            if (action == KB_SHIFT) {
              shiftOn = !shiftOn;
              drawKeyboard();
            }
            if (action == KB_PAGE){
              secondPage = !secondPage;
              drawKeyboard();
            }
          }
      }

      if(row == 3){
        int col = (screenX - startX) / keyW;
        if(col >= 2 && col < 10){
          if(typedIndex < maxChars){

            typedText[typedIndex] = ' ';
            typedIndex++;
            typedText[typedIndex] = '\0';

            charsDisplayed();
          }
        }
      }

    }

    
  }
  return false;
}

void usernameBoxTouched(){
  if(TS.touched() && (millis() - lastTouchTime) > 500){

    TS_Point cood = TS.getPoint();
    int screenX = constrain(map(cood.x, 260, 3800, 0, 320), 0, 320);
    int screenY = constrain(map(cood.y, 320, 3800, 0, 240), 0, 240);

    if((screenX >= 52 && screenX < 268) && (screenY >= 162 && screenY < 188)){
      lastTouchTime = millis();
      startKeyboard(15, SCREEN_USERNAME_INIT); 
    }
  }
}

bool nextButtonTouched(){
  if(TS.touched() && (millis() - lastTouchTime) > 200){
    
    TS_Point cood = TS.getPoint();
    int screenX = constrain(map(cood.x, 260, 3800, 0, 320), 0, 320);
    int screenY = constrain(map(cood.y, 320, 3800, 0, 240), 0, 240);

    if(screenX >= 273 && screenX < 313 && screenY >= 159 && screenY < 191 && typedIndex > 0){
      lastTouchTime = millis();
      return true;
    }
  }
  return false;
}

void settingsTouched(){

  if(TS.touched() && (millis() - lastTouchTime) > 500){
    lastTouchTime = millis();

    TS_Point cood = TS.getPoint();
    int screenX = constrain(map(cood.x, 260, 3800, 0, 320), 0, 320);
    int screenY = constrain(map(cood.y, 320, 3800, 0, 240), 0, 240);

    if(screenX >= 2 && screenX < 318){

      //return button
      if(screenX < 62 && screenY >= 2 && screenY < 32){
        currentScreen = SCREEN_DISCOVERY;
        drawScreen(currentScreen);
      }
      //Paired devices:
      if(screenY >= 37 && screenY < 90){
        currentScreen = SCREEN_PAIRED_DEVICES;
        drawScreen(currentScreen);
      }

      //Blocked devices.
      if(screenY >= 102 && screenY < 155){
        currentScreen = SCREEN_BLOCKED_DEVICES;
        drawScreen(currentScreen);
      }

      //Factory reset
      if(screenY >= 167 && screenY < 220){
        currentScreen = SCREEN_FACTORY_RESET;
        drawScreen(currentScreen);
      }
    }
  }
}

void factoryResetTouched(){

  if(TS.touched() && (millis() - lastTouchTime) > 500){
    lastTouchTime = millis();

    TS_Point cood = TS.getPoint();
    int screenX = constrain(map(cood.x, 260, 3800, 0, 320), 0, 320);
    int screenY = constrain(map(cood.y, 320, 3800, 0, 240), 0, 240);

    if(screenX >= 2 && screenX < 318){

      //return button
      if(screenX < 62 && screenY >= 2 && screenY < 32){
        currentScreen = SCREEN_SETTINGS;
        drawScreen(currentScreen);
      }

      //factory reset button
      if(screenX >= 258 && screenY >= 2 && screenY < 32){
      
      //reset screen:
      tft.fillScreen(TFT_BLACK);
      tft.drawRect(0 + 2, 0 + 2, 320 - 2 - 2, 240 - 2 - 2, TFT_WHITE);

      tft.setCursor(160 - ((12* 6 * 2)/2), 112);
      tft.print("Resetting...");

      pref.begin("Main", false);
      pref.clear();  // wipes every key in this namespace, not just "username"
      pref.end();

      pref.begin("Peers", false);
      pref.clear(); 
      pref.end();

      pref.begin("Adversaries", false);
      pref.clear();
      pref.end();
      
      delay(500);

      ESP.restart();

      }
    }
  }
}

void genericListTouched(DeviceListConfig &cfg, RowActionFn onRowTap){

  if(TS.touched() && (millis() - lastTouchTime) > 500){
    lastTouchTime = millis();

    TS_Point cood = TS.getPoint();
    int screenX = constrain(map(cood.x, 260, 3800, 0, 320), 0, 320);
    int screenY = constrain(map(cood.y, 320, 3800, 0, 240), 0, 240);

    //rows code
    if(screenY >= 30 && screenY < 210 && screenX >= 2 && screenX < 318){
      
      //gets row pressed
      int row = (screenY - 30) / 45;

      //devicescroll is only ever in integers of 4. so if on second page deviceListScroll == 4. If second row is pressed, row == 1. so deviceIndex gives 5 and devicesDisovered[deviceIndex] is the correct device.
      int deviceIndex = *cfg.scroll + row; 

      // checks if the device pressed is not higher than the amount of devices total (stops rows that don't hold anything from doing something)
      if (!(deviceIndex >= *cfg.count)) {

        //this uses the address of the inputted RowActionFn to actually be able to bring in functions as a parameter.
        onRowTap(deviceIndex);
      }

      
    }

    //arrows code
    else if(screenY >= 210 && screenY < 240){
      
      
      //right arrow
      if(screenX >= 258 && screenX < 318){

        if(rightArrowActive == true){ // checks if the arrow is even on first

          *cfg.scroll += 4;  //moves the starting index to 4, so that next rows are 4,5,6 and 7 instead of 0,1,2 and 3.
          leftArrowActive = true;
          drawGenericDeviceList(cfg); //redraws device list
        }
      }

      //left arrow
      else if(screenX >= 2 && screenX < 62){

        if(leftArrowActive == true){ 

          //moves the starting value 4 back
          *cfg.scroll -= 4;
          drawGenericDeviceList(cfg);
        }
      }
      
      
    }

    //top left code
    else if(screenY >= 2 && screenY < 32 && screenX >= 2 && screenX < 62){
      currentScreen = cfg.cornerTarget;
      drawScreen(currentScreen);
    }
  }
}

void pairScreenTouched(){
  if(TS.touched() && (millis() - lastTouchTime) > 500){
    lastTouchTime = millis();

    TS_Point cood = TS.getPoint();
    int screenX = constrain(map(cood.x, 260, 3800, 0, 320), 0, 320);
    int screenY = constrain(map(cood.y, 320, 3800, 0, 240), 0, 240);

    //cancel button
    if(screenX >= 30 && screenX < 150 && screenY >= 142 && screenY < 172){
      
      //send a MSG_ABORT with ABORT_BLOCK type to other user:
      PairAbortPacket outgoing = {};
      outgoing.type = MSG_ABORT;
      memcpy(outgoing.senderId, myDeviceId, 6);
      outgoing.abortType = ABORT_CANCEL;
      memcpy(outgoing.hash, abortValue, 32);
      sendPairPacketReliable((uint8_t*)&outgoing, sizeof(outgoing), abortValue);
      
      //clears pariring data and goes back to discovery screen.
      resetPairingState();
      drawScreen(currentScreen);
    }

    //pair // reconnect button 
    else if(screenX >= 165 && screenX < 285 && screenY >= 142 && screenY < 172){
      
      sentOwnConfirm = true;

      //sends outgoing pair confirm packet.
      PairConfirmPacket outgoing = {};
      outgoing.type = MSG_CONFIRM;
      memcpy(outgoing.senderId, myDeviceId, 6);
      memcpy(outgoing.hash, confirmValue, 32);
      sendPairPacketReliable((uint8_t*)&outgoing, sizeof(outgoing), confirmValue);

      tryPairing();

      //IF pairing is sucsseful it will reset sentOwnConfirm to false, if this is the case we dont want to redraw the pairing screen since we are alr paired.
      //IF pairing is not sucsesful, since pair button is pressed sentConfirm will always == true. redrawing replaces "Pair" with a flashing green underscore.
      if(sentOwnConfirm == true) needsPairScreenRedraw = true; 
    }

    //block button. 
    //Checks if is not in reconnection mode as block button isn't drawn when reconnecting.
    else if(screenX >= 100 && screenX < 220 && screenY >= 182 && screenY < 212 && isReconnecting == false){ 
      
      //checks if max blocked count reached
      if(blockedCount < MAX_BLOCKED){
        memcpy(blockedDevices[blockedCount].mac, pairingMac, 6);
        memcpy(blockedDevices[blockedCount].username, pairingUsername, 16);
        memcpy(blockedDevices[blockedCount].publicKey, pairingPublicKey, 32);
        blockedCount++;

        saveBlockedDevices(); //writes whole blockedDevices to flash inc new blocked.
      
        //removing the blocked device from discovery screen by finding it.
        for(int i = 0; i < discoveredCount; i++){
          
          if(memcmp(pairingMac, discoveredDevices[i].mac, 6) == 0){ //if the mac of pairing mac matches discoveredDevices[i].mac, we found them.

            for(int j = i; j < discoveredCount - 1; j++){//moves all devices after removed device back one.
              discoveredDevices[j] = discoveredDevices[j + 1];
            }
            discoveredCount--;
            updateDiscoveryScreen = true;
            break; // escapes int i for loop since we alr found the device.
          }
        }
        
        //send a MSG_ABORT with ABORT_BLOCK type to other user:
        PairAbortPacket outgoing = {};
        outgoing.type = MSG_ABORT;
        memcpy(outgoing.senderId, myDeviceId, 6);
        outgoing.abortType = ABORT_BLOCK;
        memcpy(outgoing.hash, abortValue, 32);
        sendPairPacketReliable((uint8_t*)&outgoing, sizeof(outgoing), abortValue);


        //goes back to discovery screen after blocking.
        resetPairingState();
        drawScreen(currentScreen);
      }

      //if the max_devices has been reached: 
      else{
        resetPairingState();
        popup("MAX BLOCKED DEVICES", SCREEN_DISCOVERY, TFT_RED);
      }
    }

  }
}

void chatTouched(){
  if(TS.touched() && (millis() - lastTouchTime) > 300){
    lastTouchTime = millis();

    TS_Point cood = TS.getPoint();
    int screenX = constrain(map(cood.x, 260, 3800, 0, 320), 0, 320);
    int screenY = constrain(map(cood.y, 320, 3800, 0, 240), 0, 240);

    // X button
    if(screenX >= 2 && screenX < 62 && screenY >= 2 && screenY < 32){
      messageCount = 0;
      chatScroll = 0;
      deviceMode = MODE_DISCOVERING;
      currentScreen = SCREEN_DISCOVERY;
      drawScreen(currentScreen);
      return;
    }

    // text box to keyboard
    if(screenX >= 2 && screenX < 258 && screenY >= 180 && screenY < 210){
      startKeyboard(125, SCREEN_CHAT);
      return;
    }

    // send button
    if(screenX >= 258 && screenX < 318 && screenY >= 180 && screenY < 210){
      if(typedIndex > 0 && !awaitingAck){
        sendEncryptedText(typedText);
        typedIndex = 0;
        typedText[0] = '\0';
        updateChatScreen = true;
      }
      return;
    }

    // left arrow
    if(leftArrowActive && screenX >= 2 && screenX < 62 && screenY >= 210 && screenY < 240){
      chatScroll = chatPrevPageStart(chatScroll);
      drawScreen(SCREEN_CHAT);
      return;
    }

    // right arrow
    if(rightArrowActive && screenX >= 258 && screenX < 318 && screenY >= 210 && screenY < 240){
      chatScroll = chatPageEnd(chatScroll);
      drawScreen(SCREEN_CHAT);
      return;
    }
  }
}

//action functions for genericListTouched():

void onDiscoveryRowTap(int i){
  if(deviceMode != MODE_DISCOVERING) return; // ignore re-taps while already pending

  //copies all user data to global variables to be paired with.
  memcpy(pairingMac, discoveredDevices[i].mac, 6);
  memcpy(pairingUsername, discoveredDevices[i].username, 16);
  memcpy(pairingPublicKey, discoveredDevices[i].publicKey, 32);

  for(int j = 0; j < 16; j++) myRandNum[j] = esp_random() & 0xFF; //generating own randNum. 

  //makes the actual packet
  PairRequestPacket outgoing = {};
  outgoing.type = MSG_PAIR_REQUEST;
  memcpy(outgoing.senderId, myDeviceId, 6);
  outgoing.currentlyPaired = isPaired(pairingMac, pairingUsername, pairingPublicKey);
  Username.toCharArray(outgoing.username, 16);
  memcpy(outgoing.publicKey, myPublicKey, 32);
  memcpy(outgoing.randNum, myRandNum, 16);

  //sends it off
  sendLoRa((uint8_t*)&outgoing, sizeof(outgoing));

  //waiting for reply now.
  pendingStartTime = millis();
  deviceMode = MODE_PENDING;
  popup("Connecting...", SCREEN_DISCOVERY, TFT_WHITE);
}

void onPairedRowTap(int i){
  // paired count - 1 because we use j + 1 and dont want to go over memory
  for(int j = i; j < pairedCount - 1; j++){
    pairedDevices[j] = pairedDevices[j + 1];
  }
  pairedCount--;
  savePairedDevices();

  updatePairedScreen = true;
}

void onBlockedRowTap(int i){
  for(int j = i; j < blockedCount - 1; j++){
    blockedDevices[j] = blockedDevices[j + 1];
  }
  blockedCount--;
  saveBlockedDevices();

  updateBlockedScreen = true;
}


// Keyboard functions
void drawKeyboard() {
  //clears display first
  tft.fillScreen(TFT_BLACK);

  //checks what page we are on based on if '|' is pressed or not. 
  if (secondPage) {
  rowPointer[0] = row0_page2; rowPointer[1] = row1_page2; rowPointer[2] = row2_page2;
  secondPage = true;
  } else {
  rowPointer[0] = row0; rowPointer[1] = row1; rowPointer[2] = row2;
  secondPage = false;
  }

  for (int row = 0; row < 3; row++){
    
    for (int col = 0; col < rowSizes[row]; col++) {
      int x;

      switch (row){
        case 0:
          x = row0offset + col * keyW;
          break;

        case 1:
          x = row1offset + col * keyW;
          break;

        case 2:
          if(col == 0){
            x = row2offset + col * keyW;
          }
          else{
            x = row2offset + keyW + col * keyW;
          }

          break;
      }

      int y = startY + (keyH * row);

      tft.drawRect(x, y, keyW * rowPointer[row][col].sizeMult, keyH, TFT_WHITE);
      tft.drawChar(x + 10 - 4, y + 10 + 4, shiftOn ? toupper(rowPointer[row][col].label) : rowPointer[row][col].label, TFT_WHITE, TFT_BLACK, 2); 
    }

  }

  tft.drawRect((320 - (keyW * 8))/2 , startY + (keyH * 3) , keyW * 8 , 30 , TFT_WHITE);
  charsDisplayed();
}

void charsDisplayed(){


  //redraws the text at the top every time by clearing the whole top then re printing
  tft.fillRect(0,0,320,startY,TFT_BLACK);
  tft.setViewport(10, 10, 310, 230);
  tft.setCursor(0,0);
  tft.print(typedText);

  //get coods of last word before closing viewport for the underscore.
  charX = tft.getCursorX();
  charY = tft.getCursorY();

  tft.resetViewport();

  tft.setTextSize(1);

  int charsLeft = maxChars-typedIndex;
  tft.fillRect(320 - 21, startY - 15, 20, 10, TFT_BLACK);
  if(charsLeft<=10) tft.setTextColor(TFT_RED);
  else if(charsLeft<=30) tft.setTextColor(TFT_YELLOW);
  else tft.setTextColor(TFT_WHITE);

  tft.setCursor(320 - 21, startY - 11); //chars at size 1 are 6 wide, 8 tall. + 3 offset off the wall.
  tft.print(charsLeft);
  tft.setTextColor(TFT_WHITE);

  tft.setTextSize(2);

}

void startKeyboard(int charLim, int returnScreen){
  maxChars = min(charLim,120);
  typedIndex = 0;
  typedText[0] = '\0';

  keyboardReturnScreen = returnScreen;
  currentScreen = SCREEN_KEYBOARD; 

  drawKeyboard();
}

void updateCursorBlink(int x, int y, int colour, bool active) {
    if (millis() - lastBlinkTime < 500) return;
    lastBlinkTime = millis();
    underscoreOn = !underscoreOn;
    if (active) tft.drawChar(x, y, '_', underscoreOn ? colour : TFT_BLACK, TFT_BLACK, 2);
}

//screen functions
void drawScreen(int screen) {
  switch(screen) {
    case SCREEN_USERNAME_INIT:   usernameInitPage(); break;
    case SCREEN_DISCOVERY:       drawGenericDeviceList(discoveryConfig); break;
    case SCREEN_SETTINGS:        drawSettings(); break;
    case SCREEN_FACTORY_RESET:   drawFactoryReset(); break;
    case SCREEN_PAIRED_DEVICES:  drawGenericDeviceList(pairedConfig); break;
    case SCREEN_BLOCKED_DEVICES: drawGenericDeviceList(blockedConfig); break;
    case SCREEN_PAIR_CODES:     drawPairScreen(); break;
    case SCREEN_CHAT: drawTextChat(); break;
    // SCREEN_KEYBOARD excluded since its only entered via startKeyboard(), not drawScreen()
  }
}

void updateScreen() {
  if(updatePopup){
    popup((const char*)popupText, popupReturnScreen, popupColour);
    updatePopup = false; 
  }

  switch(currentScreen) {
    case SCREEN_USERNAME_INIT:
      updateCursorBlink(154, 167, TFT_WHITE, typedIndex == 0);
      usernameBoxTouched();
      
      if (nextButtonTouched()) finishFirstBoot();
      break;

    case SCREEN_KEYBOARD:
      if (updateKeyboard()) {
        currentScreen = keyboardReturnScreen;
        drawScreen(currentScreen);
      }
      updateCursorBlink(charX + 10, charY + 10, TFT_WHITE, currentScreen == SCREEN_KEYBOARD);
      break;

    case SCREEN_DISCOVERY:       
      if(updateDiscoveryScreen == true) {
        drawScreen(SCREEN_DISCOVERY);

        updateDiscoveryScreen = false;
      }

      if(updateSignal == true){
        drawSignal(discoveryConfig);
        updateSignal = false;
      }

      genericListTouched(discoveryConfig, onDiscoveryRowTap);
      break;
    
    case SCREEN_SETTINGS:        settingsTouched(); break;
    case SCREEN_FACTORY_RESET:   factoryResetTouched(); break;

    case SCREEN_PAIRED_DEVICES:
      //refreshes if device unpaired
      if(updatePairedScreen){
        updatePairedScreen = false;
        drawScreen(currentScreen);
      }
      
      genericListTouched(pairedConfig, onPairedRowTap);
      break;

    case SCREEN_BLOCKED_DEVICES: 
      //refreshes if device unblocked
      if(updateBlockedScreen){
        updateBlockedScreen = false;
        drawScreen(currentScreen);
      }

      genericListTouched(blockedConfig, onBlockedRowTap); 
      break;

    case SCREEN_PAIR_CODES:
      if(needsPairScreenRedraw){
        needsPairScreenRedraw = false;
        drawScreen(currentScreen);
      }
      updateCursorBlink(219, 149, TFT_GREEN, sentOwnConfirm);
      pairScreenTouched();
      break;
    
    case SCREEN_POPUP:{
      if(millis() - popupStartTime > 1000){
        currentScreen = popupReturnScreen;
        drawScreen(currentScreen);
      }
      break;
    }
    

    case SCREEN_CHAT:
      if(updateChatScreen){
      updateChatScreen = false;
      drawScreen(SCREEN_CHAT);
      }
      chatTouched();
      break;
  }
}

void setup() {
  Serial.begin(115200);

  //used to read the actual MAC of the esp32. We use this as the radio mac.
  esp_read_mac(myDeviceId, ESP_MAC_WIFI_STA);

  //load paired and blocked devices. 
  loadPairedDevices();
  loadBlockedDevices();

  //begins LoRa uart communication.
  LoRaSerial.begin(9600, SERIAL_8N1, LoRaRX, LoRaTX);
  
  //XPT2046 initialisation
  TouchSPI.begin(T_CLK,T_MISO,T_MOSI,T_CS);
  TS.begin(TouchSPI);

  //TFT_eSPI initialisation
  tft.init();
  tft.invertDisplay(0);
  tft.setRotation(1);
  tft.setTextSize(2);
  tft.fillScreen(TFT_BLACK);

  //RNG initialisation
  RNG.begin("ESP_Encrypt");

  //boot
  bootScreen();
  bootSequence();
}


void loop() {
  pollLoRaReceive();
  runProtocolLogic();
  updateScreen();
}