#include <arpa/inet.h>

/*
Estructura donde se van a almacenar los conteos de los paquetes de capa superior
así como los conteos de protocolo de Ethernet II e IEEE 802.3.
*/
typedef struct analisis{
    int ipv4;
    int ipv6;
    int arp;
    int ethh_stream_control;
    int mac_security;
    int ethh2;
    int ieee802_3;
} Analisis;

/*
Estructura donde se van a almacenar los paquetes temporalmente
*/
typedef struct EthernetCustom{
    struct ethhdr * ethernet;
    int size;
} EthernetCustom;