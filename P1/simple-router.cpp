/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
void SimpleRouter::handleArpPacket (arp_hdr *arp_hd, const Interface* iface) {
  // Check if addresses matched
  if (arp_hd->arp_tip != iface->ip) {
    std::cerr << "Received packet, but addresses are mismatched, ignoring\n" << std::endl;
    return;
  }

  unsigned short op = ntohs(arp_hd->arp_op);
  switch(op) {
    case arp_op_request: {
        // Prepare and send an ARP reply packet
        std::cerr << "Received ARP request, replying\n" << std::endl;
        Buffer packetBuffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        uint8_t* rep_pack = (uint8_t *) packetBuffer.data();
        ethernet_hdr* rep_eth_hd = (ethernet_hdr *) rep_pack;
        arp_hdr* rep_arp_hd = (arp_hdr *) (rep_pack + sizeof(ethernet_hdr));
        // Ethernet header
        memcpy(rep_eth_hd->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(rep_eth_hd->ether_dhost, arp_hd->arp_sha, ETHER_ADDR_LEN);
        rep_eth_hd->ether_type = htons(ethertype_arp);
        // ARP header
        rep_arp_hd->arp_hrd = htons(arp_hrd_ethernet);
        rep_arp_hd->arp_pro = htons(ethertype_ip);
        rep_arp_hd->arp_hln = ETHER_ADDR_LEN;
        rep_arp_hd->arp_pln = 4;
        rep_arp_hd->arp_op = htons(arp_op_reply);
        memcpy(rep_arp_hd->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
        rep_arp_hd->arp_sip = iface->ip;
        memcpy(rep_arp_hd->arp_tha, arp_hd->arp_sha, ETHER_ADDR_LEN);
        rep_arp_hd->arp_tip = arp_hd->arp_sip;
        // Send reply packet
        // print_hdrs(packetBuffer);
        sendPacket(packetBuffer, iface->name);
      }
      break;

    case arp_op_reply: {
        std::cerr << "Received ARP reply, sending out enqueued packets\n" << std::endl;
        Buffer mac(arp_hd->arp_sha, arp_hd->arp_sha + sizeof(arp_hd->arp_sha));
        std::shared_ptr<ArpRequest> req_ptr = m_arp.insertArpEntry(mac, arp_hd->arp_sip);
        // No request for the received reply
        if (req_ptr == NULL) {
          std::cerr << "There is no request, ignoring\n" << std::endl;
          return;
        }
        // Send enqueued packets that were waiting for the received reply
        std::list<PendingPacket>req_packets = req_ptr->packets;
        for (auto const& it : req_packets) {
          Buffer packet = it.packet;
          ethernet_hdr *eth_hd = (ethernet_hdr *) packet.data();
          memcpy(eth_hd->ether_dhost, arp_hd->arp_sha, ETHER_ADDR_LEN);         
          // print_hdrs(packet);
          sendPacket(packet, it.iface);
        }
        // Done with the queue, remove it
        m_arp.removeRequest(req_ptr);
      }
      break;
    default: {
      std::cerr << "Received packet, but ARP type is unknown, ignoring\n" << std::endl;
      return;
    }
  }
}

void SimpleRouter::handleIpPacket (ip_hdr *ip_hd, const Interface* iface, unsigned int length) {
  // Check ip version
  if (ip_hd->ip_v != 4) {
    std::cerr << "Received non-IPv4 packet, ignoring\n" << std::endl;
    return;
  }

  // Verify checksum
  uint16_t chks = ip_hd->ip_sum;
  ip_hd->ip_sum = 0;
  if (cksum(ip_hd, sizeof(ip_hdr)) != chks) {
    std::cerr << "Received IPv4 packet, but bad checksum, ignoring\n" << std::endl;
    return;    
  }
  ip_hd->ip_sum = chks;

  // Forward or discard
  const Interface* ifc = findIfaceByIp(ip_hd->ip_dst);
  if (ifc) {
    std::cerr << "Packet is for me, ignoring\n" << std::endl;
    return;
  }
  else {
    std::cerr << "Packet is to be forwarded" << std::endl;
    // Look up next-hop IP addr
    RoutingTableEntry rte = m_routingTable.lookup(ip_hd->ip_dst);
    uint32_t nh_ip = rte.gw;
    std::cerr << "Next hop IP addr: " << ipToString(nh_ip) << std::endl;
    // Decrement TTL
    uint8_t ttl = ip_hd->ip_ttl - 1;
    if (ttl == 0) {
      std::cerr << "TTL is 0, ignoring\n" << std::endl;
      return;
    }
    ip_hd->ip_ttl = ttl;
    // Recompute checksum
    ip_hd->ip_sum = 0;
    ip_hd->ip_sum = cksum(ip_hd, sizeof(ip_hdr));
    // Forward packet
    Buffer packetBuffer(sizeof(ethernet_hdr) + length);
    uint8_t* fwd_pack = (uint8_t *) packetBuffer.data();
    memcpy(fwd_pack + sizeof(ethernet_hdr), ip_hd, length);
    ethernet_hdr* fwd_eth_hd = (ethernet_hdr *) fwd_pack;
    const Interface* rte_iface = findIfaceByName(rte.ifName);  
    memcpy(fwd_eth_hd->ether_shost, rte_iface->addr.data(), ETHER_ADDR_LEN);           
    fwd_eth_hd->ether_type = htons(ethertype_ip);

    std::shared_ptr<ArpEntry> arp_en = m_arp.lookup(nh_ip);
    if (arp_en != NULL) { // Found ARP entry, send to that mac addr
      std::cerr << "Found an ARP entry, sending packet to interface " << rte.ifName << std::endl << std::endl;
      memcpy(fwd_eth_hd->ether_dhost, arp_en->mac.data(), ETHER_ADDR_LEN);  
      // print_hdrs(packetBuffer);
      sendPacket (packetBuffer, rte.ifName);
    }
    else { // No ARP entry found, send ARP request and queue received packet
      std::cerr << "Found no ARP entry, sending ARP request\n" << std::endl;
      // Put the packet on queue
      std::shared_ptr<ArpRequest> req_ptr = m_arp.queueRequest(nh_ip, packetBuffer, rte.ifName);
      // Check if an ARP request has not been sent
      if (req_ptr->nTimesSent == 0) {
        // Create and send an ARP request
        Buffer req_pack_buffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        uint8_t* req_pack = (uint8_t *) req_pack_buffer.data();
        ethernet_hdr* eth_hd = (ethernet_hdr *)req_pack;
        arp_hdr* arp_hd = (arp_hdr *)(req_pack + sizeof(ethernet_hdr));
        // Ethernet header
        memcpy(eth_hd->ether_shost, rte_iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(eth_hd->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);
        eth_hd->ether_type = htons(ethertype_arp);
        // ARP header
        arp_hd->arp_hrd = htons(arp_hrd_ethernet);
        arp_hd->arp_pro = htons(ethertype_ip);
        arp_hd->arp_hln = ETHER_ADDR_LEN;
        arp_hd->arp_pln = 4;
        arp_hd->arp_op = htons(arp_op_request);
        memcpy(arp_hd->arp_sha, rte_iface->addr.data(), ETHER_ADDR_LEN);
        arp_hd->arp_sip = rte_iface->ip;
        memcpy(arp_hd->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);
        arp_hd->arp_tip = nh_ip;
        // Send ARP request
        // print_hdrs(req_pack_buffer);
        sendPacket(req_pack_buffer, rte.ifName);  
        // Update time-related vars
        req_ptr->nTimesSent++;
        req_ptr->timeSent = steady_clock::now();    
      }   
    }
  }
}

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  // Find input network interface
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring\n" << std::endl;
    return;
  }
  std::cerr << getRoutingTable() << std::endl;

  // Read possible ethernet header and check eth_type field
  ethernet_hdr *eth_hd = (ethernet_hdr*) packet.data();
  const uint8_t *eth_dhost = eth_hd->ether_dhost;

  if (memcmp(eth_dhost, BroadcastEtherAddr , ETHER_ADDR_LEN) == !0)
    std::cerr << "Received packet, but addresses are mismatched, ignoring\n" << std::endl;

  uint16_t eth_tp= ntohs(eth_hd->ether_type);
  switch(eth_tp) {
    case ethertype_arp: {
        unsigned int arp_packet_size = packet.size() - sizeof(ethernet_hdr);
        if (arp_packet_size < sizeof(arp_hdr)) {
          std::cerr << "Received ARP packet, but length is less than the minimum, ignoring\n" << std::endl;
          return;
        }       
        // std::cerr << "Received ARP packet: " << std::endl;
        // print_hdrs(packet);
        arp_hdr *arp_hd = (arp_hdr*) (packet.data() + sizeof(ethernet_hdr));
        handleArpPacket (arp_hd, iface);
      }
      break;
    case ethertype_ip: {
        unsigned int ip_packet_size = packet.size() - sizeof(ethernet_hdr);
        if (ip_packet_size < sizeof(ip_hdr)) {
          std::cerr << "Received IP packet, but length is less than the minimum, ignoring\n" << std::endl;
          return;
        }
        // std::cerr << "Received IP packet: " << std::endl;
        // print_hdrs(packet);        
        ip_hdr *ip_hd = (ip_hdr*) (packet.data() + sizeof(ethernet_hdr));
        handleIpPacket (ip_hd, iface, ip_packet_size);
      }
      break;
    default:
      std::cerr << "Received packet, but type is unknown, ignoring\n" << std::endl;
      return;
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
