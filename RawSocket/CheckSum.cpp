#include <RawSocket/CheckSum.h>
#include <cstdio>

struct PseudoHead{
  uint8_t zero;
  uint8_t type;
  uint16_t  len;
  in_addr src_ip;
  in_addr dst_ip;
};

static uint32_t CalSum(const uint8_t* buf, int len) {
  uint32_t sum = 0;
  const uint8_t* p = buf;
  for(; len > 1; len -= 2) {
    sum += (*p << 8)+ *(p + 1);
    p += 2;
  }
  if (len == 1)
    sum += *p << 8;  //
    //sum += *p;  //
  return sum;
}

static uint32_t CalPseudoHeadSum(const iphdr* pIpHead, uint8_t type) {
  PseudoHead head;
  head.zero = 0;
  head.type = type;
  head.len = htons(static_cast<uint16_t>(ntohs(pIpHead->ip_len) - pIpHead->ip_hl * 4));
  head.src_ip = pIpHead->ip_src;
  head.dst_ip = pIpHead->ip_dst;
  return CalSum((uint8_t*)&head, sizeof(PseudoHead));
}

uint16_t cksumIp(iphdr* pIpHead){
  pIpHead = 0;
  uint32_t ckSum = CalSum((uint8_t*)pIpHead, pIpHead->ip_hl * 4);
  ckSum = (ckSum >> 16) + (ckSum & 0xffff);
  ckSum += ckSum >> 16;
  return htons((uint16_t)~ckSum);
}

uint16_t cksumTcp(iphdr* pIpHead, tcphdr* pTcpHead){
  pTcpHead = 0;
  uint32_t ckSum = CalPseudoHeadSum(pIpHead, 0x06);
  ckSum += CalSum((uint8_t*)pTcpHead,
      ntohs(pIpHead->ip_len) - pIpHead->ip_hl * 4);
  ckSum = (ckSum >> 16) + (ckSum & 0xffff);
  ckSum += ckSum >> 16;
  return htons((uint16_t)~ckSum);
}
