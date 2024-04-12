cmake_minimum_required(VERSION 3.8)

project(btmon)
set(CMAKE_C_FLAGS_DEBUG "-g -fsanitize=address")

include_directories(.)
add_executable(btmon
   main.c
   lib/hci.c
   lib/uuid.c
   lib/bluetooth.c
   src/shared/util.c
   src/shared/queue.c
   src/shared/crypto.c
   src/shared/gatt-db.c
   src/shared/bap-debug.c
   monitor/a2dp.c
   monitor/analyze.c
   monitor/att.c
   monitor/avctp.c
   monitor/avdtp.c
   monitor/bnep.c
   monitor/broadcom.c
   monitor/control.c
   monitor/crc.c
   monitor/hwdb.c
   monitor/intel.c
   monitor/keys.c
   monitor/l2cap.c
   monitor/ll.c
   monitor/lmp.c
   monitor/msft.c
   monitor/packet.c
   monitor/rfcomm.c
   monitor/sdp.c
   monitor/vendor.c
)

target_link_options(btmon PRIVATE -sEXPORTED_FUNCTIONS=_malloc)
