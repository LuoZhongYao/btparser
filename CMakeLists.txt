project(btuart)
cmake_minimum_required(VERSION 3.8)
set(CMAKE_C_FLAGS_DEBUG "-g -fsanitize=address")

add_executable(btparser
	main.c
	parser/amp.c
	parser/att.c
	parser/avctp.c
	parser/avdtp.c
	parser/avrcp.c
	parser/bnep.c
	parser/bpa.c
	parser/capi.c
	parser/cmtp.c
	parser/csr.c
	parser/ericsson.c
	parser/hci.c
	parser/hcrp.c
	parser/hidp.c
	parser/l2cap.c
	parser/lmp.c
	parser/obex.c
	parser/parser.c
	parser/ppp.c
	parser/rfcomm.c
	parser/sap.c
	parser/sdp.c
	parser/smp.c
	parser/tcpip.c
	)

target_link_libraries(btparser PRIVATE bluetooth)
target_include_directories(btparser PRIVATE include)

add_library(bluetooth)
target_sources(bluetooth PRIVATE
	lib/hci.c
	lib/bluetooth.c)
target_include_directories(bluetooth PRIVATE include/bluetooth)
