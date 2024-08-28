
curl https://opensource.apple.com/source/xnu/xnu-3789.41.3/bsd/net/pktap.h -o pktap.h
curl https://opensource.apple.com/source/libpcap/libpcap-67/libpcap/pcap/pcap.h -o pcap.h
curl https://opensource.apple.com/source/xnu/xnu-3789.41.3/bsd/net/bpf.h -o bpf.h

// PF API: 
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h 
// SDK_PATH=$(xcodebuild -sdk macosx Path -version)
// Include: -I"$SDK_PATH/System/Library/Frameworks/Kernel.framework/Versions/A/Headers"
// Example:
// /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.2.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers