int is_control_packet(sstp_packet_t* pkt) 
{
  return pkt->reserved & 1;
}


