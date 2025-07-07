#include <iostream>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;

class Config {
public:
    Config()
    {
        ifstream config_file(CONFIG_FILE_PATH);
        if (!config_file.is_open()) {
            throw runtime_error("Could not open config file: " + string(CONFIG_FILE_PATH));
        }

        try {
            config_file >> config;
        } catch (const json::parse_error& e) {
            throw runtime_error("Error parsing JSON config: " + string(e.what()));
        }

        if (!config.contains("pcap-file") || !config["pcap-file"].is_string()) {
            throw runtime_error("Config missing 'pcap-file' key or it is not a string.");
        }
    }

    string getPcapFilePath() const
    {
        return config["pcap-file"].get<string>();
    }

private:
    json config;
};

int main(int argc, char* argv[])
{
    Config config;
    string pcap_file = config.getPcapFilePath();

    // open a pcap file for reading
    pcpp::PcapFileReaderDevice reader(pcap_file);
    if (!reader.open())
    {
        std::cerr << "Error opening the pcap file" << std::endl;
        return 1;
    }

    // read the first (and only) packet from the file
    pcpp::RawPacket rawPacket;
    if (!reader.getNextPacket(rawPacket))
    {
        std::cerr << "Couldn't read the first packet in the file" << std::endl;
        return 1;
    }

    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    // verify the packet is IPv4
    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {
        // extract source and dest IPs
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

        // print source and dest IPs
        std::cout
          << "Source IP is '" << srcIP << "'; "
          << "Dest IP is '" << destIP << "'"
          << std::endl;
    }

    // close the file
    reader.close();

    return 0;
}