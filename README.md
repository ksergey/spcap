# spcap
C++ PCAP parsing library

# Features
- Parsing PCAPs from xz-encoded files directly
- Nanoseconds timestamp precision
- Header-only

# Limitations
- Only Ethernet frames
- Only UDP packets
- Only little-endian

# Dependencies
- liblzma - decoding xz-archives
- cmake - build system
