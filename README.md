# CVE-2015-6620-POC-1
POC for one bug in CVE-2015-6620-1 (ANDROIDID-24123723), AMessage unmarshal arbitrary write. The two bugs are merged to one CVE, and here is POC for one of them.

##Explaination


	533 sp<AMessage> AMessage::FromParcel(const Parcel &parcel) {
	534    int32_t what = parcel.readInt32();
	535    sp<AMessage> msg = new AMessage(what);
	536
	537    msg->mNumItems = static_cast<size_t>(parcel.readInt32()); //mNumItems can be set by attacker
	538    for (size_t i = 0; i < msg->mNumItems; ++i) {
	539        Item *item = &msg->mItems[i];
	540
	541        const char *name = parcel.readCString();
	542        item->setName(name, strlen(name));
	543        item->mType = static_cast<Type>(parcel.readInt32());
	544
	545        switch (item->mType) {
	547            {
	548                item->u.int32Value = parcel.readInt32();//overwrite out-of-bound
	549                break;
	550            }

...

	65 void AMessage::clear() {
	66    for (size_t i = 0; i < mNumItems; ++i) {
	67        Item *item = &mItems[i];
	68        delete[] item->mName; //maybe freeing the wrong pointer if i ran out-of-bound
	69        item->mName = NULL;
	70        freeItemValue(item);
	71    }
	72    mNumItems = 0;
	73}


The msg->mItems is an array of fixed size `kMaxNumItems`=64, however when AMessage is unmarshalled, the loop counter can be set far beyond this limit, thus lead to memory overwrite or arbitrary freeing, then memory corruption.

Then we need to find a binder interface that will unmarshal the AMessage and can be called by unprivileged application. Through searching I found that the IStreamListener->issueCommand is a callback that accepts transaction from normal client, then processed at the mediaserver side. And it will construct AMessage from input parcel. 

To get an IStreamListener, one way is create a BnStreamSource and provide to MediaPlayer->setDataSource, then when playing MediaPlayer will call the setListener method of your BnStreamSource Implementation, providing the client an IStreamListener and communicate control params via AMessage. So, we provide our fake AMessage here. Boom!

##Test method:

Build the POC with name `stream`, then ran with `adb shell stream ts-file-name`. I use a TS media file to trigger the binder callback for simplicity, but there should be better options.

##Sample crash:

	F/libc    (17405): Fatal signal 11 (SIGSEGV), code 1, fault addr 0xdfe85000 in tid 17511 (streaming)
	I/DEBUG   (  355): *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
	I/DEBUG   (  355): Build fingerprint: 'google/shamu/shamu:5.1.1/LMY48I/2074855:user/release-keys'
	I/DEBUG   (  355): Revision: '33696'
	I/DEBUG   (  355): ABI: 'arm'
	W/NativeCrashListener(  839): Couldn't find ProcessRecord for pid 17405
	I/DEBUG   (  355): pid: 17405, tid: 17511, name: streaming  >>> /system/bin/mediaserver <<<
	E/DEBUG   (  355): AM write failure (32 / Broken pipe)
	I/DEBUG   (  355): signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0xdfe85000
	I/DEBUG   (  355):     r0 29685000  r1 d6d5d4d9  r2 b6802e74  r3 fff29685
	I/DEBUG   (  355):     r4 b6800000  r5 000003df  r6 b6802e8c  r7 c81fff19
	I/DEBUG   (  355):     r8 b6be24b8  r9 000003e2  sl b380bbac  fp b6e65fd8
	I/DEBUG   (  355):     ip 0000000c  sp b380bac0  lr b6e31b3d  pc b6e31af6  cpsr 200f0030
	I/DEBUG   (  355): 
	I/DEBUG   (  355): backtrace:
	I/DEBUG   (  355):     #00 pc 00041af6  /system/lib/libc.so (je_arena_dalloc_bin+41)
	I/DEBUG   (  355):     #01 pc 00041b39  /system/lib/libc.so (je_arena_dalloc_small+28)
	I/DEBUG   (  355):     #02 pc 000498b3  /system/lib/libc.so (ifree+462)
	I/DEBUG   (  355):     #03 pc 00012caf  /system/lib/libc.so (free+10)
	I/DEBUG   (  355):     #04 pc 0000c943  /system/lib/libstagefright_foundation.so (android::AMessage::clear()+24)
	I/DEBUG   (  355):     #05 pc 0000c973  /system/lib/libstagefright_foundation.so (android::AMessage::~AMessage()+18)
	I/DEBUG   (  355):     #06 pc 0000c98d  /system/lib/libstagefright_foundation.so (android::AMessage::~AMessage()+4)
	I/DEBUG   (  355):     #07 pc 0000ec55  /system/lib/libutils.so (android::RefBase::decStrong(void const*) const+40)
	I/DEBUG   (  355):     #08 pc 0003a679  /system/lib/libmediaplayerservice.so (android::sp<android::SharedLibrary>::~sp()+10)
	I/DEBUG   (  355):     #09 pc 0005bbeb  /system/lib/libmediaplayerservice.so
	I/DEBUG   (  355):     #10 pc 0005be71  /system/lib/libmediaplayerservice.so (android::NuPlayer::NuPlayerStreamListener::read(void*, unsigned int, android::sp<android::AMessage>*)+216)
	I/DEBUG   (  355):     #11 pc 000580fb  /system/lib/libmediaplayerservice.so (android::NuPlayer::StreamingSource::onReadBuffer()+50)
	I/DEBUG   (  355):     #12 pc 00058271  /system/lib/libmediaplayerservice.so (android::NuPlayer::StreamingSource::onMessageReceived(android::sp<android::AMessage> const&)+20)
	I/DEBUG   (  355):     #13 pc 0000c4c3  /system/lib/libstagefright_foundation.so (android::ALooperRoster::deliverMessage(android::sp<android::AMessage> const&)+166)
	I/DEBUG   (  355):     #14 pc 0000be45  /system/lib/libstagefright_foundation.so (android::ALooper::loop()+220)
	I/DEBUG   (  355):     #15 pc 000104d5  /system/lib/libutils.so (android::Thread::_threadLoop(void*)+112)
	I/DEBUG   (  355):     #16 pc 00010045  /system/lib/libutils.so
	I/DEBUG   (  355):     #17 pc 00016baf  /system/lib/libc.so (__pthread_start(void*)+30)
	I/DEBUG   (  355):     #18 pc 00014af3  /system/lib/libc.so (__start_thread+6)
	I/DEBUG   (  355): 
	I/DEBUG   (  355): Tombstone written to: /data/tombstones/tombstone_04
