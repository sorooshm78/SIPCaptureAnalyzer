cmake_minimum_required(VERSION 3.10)
project(SIPCaptureAnalyzer)

set(CMAKE_CXX_STANDARD 20)

add_executable(SIPCaptureAnalyzer src/main.cpp)

set(CONFIG_PATH "${CMAKE_CURRENT_SOURCE_DIR}/config.json")
target_compile_definitions(SIPCaptureAnalyzer
    PRIVATE CONFIG_FILE_PATH=\"${CONFIG_PATH}\")

find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(PcapPlusPlus REQUIRED)

target_link_libraries(SIPCaptureAnalyzer nlohmann_json::nlohmann_json)
target_link_libraries(SIPCaptureAnalyzer
    PcapPlusPlus::Pcap++
    PcapPlusPlus::Packet++
    PcapPlusPlus::Common++
)
