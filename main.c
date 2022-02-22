#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "mac_plot_list.h"
#include "sniffer.h"
#include <pthread.h>

/*
    Se crean los métodos que se van a utilizar para el programa.
*/
void deactivatePromiscMode(char * card_interface);
void clasifyDifusion(unsigned char d);
void clasifyProtocol(unsigned short d);

Analisis * analisis; //Variable que nos ayudará a generar el resumen de nuestro análisis.
Nodo * nodo = NULL; //Variable que nos ayudará a clasificar las tramas de las direcciones MAC.
FILE * fp; //Variable que nos permitira vaciar la información en un archivo de texto.

void *analizer(void * data); //Método que permite la creación de un proceso concurrente

int main(){

    int packets = 0; //Variable donde se van a almacenar los paquetes

    void *valor_retorno; //Variable en caso de que deseemos que nuestro hilo hijo regrese algún valor.

    analisis = (Analisis *) malloc(sizeof(Analisis)); //Se reserva memoria para nuestra estructura de Análisis
    //Se inicializan los atributos de nuestra estructura
    analisis->arp = 0;
    analisis->ethh2 = 0;
    analisis->ethh_stream_control = 0;
    analisis->ieee802_3 = 0;
    analisis->ipv4 = 0;
    analisis->ipv6 = 0;
    analisis->mac_security = 0;

    struct ifreq ethreq; //Variable donde vamos a configurar nuestra tarjeta de red
    int sock; //Variable para nuestro socket.
    char * cardInterface = (char *) calloc(100, sizeof(char)); //Se reserva memoria para la entrada de teclado
    
    //Se solicita el número de paquetes al usuarios
    printf("\nInserta el número de paquetes\n");
    scanf("%i", &packets);
    pthread_t anlzr[packets];

    fflush(stdin);// Se limpia el buffer de entrada

    //Se solicita el nombre de la tarjeta de red
    printf("\nInserta el nombre de tu tarjeta de red\n");
    scanf("%s", cardInterface);

    printf("Esta es la tarjeta %s", cardInterface);

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));//Se configura el socket para poder acepttar todos los paquetes entrantes

    strncpy(ethreq.ifr_name, cardInterface, IFNAMSIZ);//Se configura el socket a la tarjeta de red
    ioctl(sock, SIOCGIFFLAGS, &ethreq); //Se configuran la entrada y salida de paquetes para la tarjeta de red
    ethreq.ifr_flags |= IFF_PROMISC; //Se coloca la bandarea para que la tarjeta entre en modo promiscuo
    ioctl(sock, SIOCSIFFLAGS, &ethreq);//Se configura la tarjeta en modo promiscuo

    struct sockaddr saddr; //Variable que permite tener el socket abierto en todo momento
    int size_saddr; //variable que permite almacenar la longitud de las direcciones

    fp = fopen("analisis.txt", "a"); //Se abre el archivo de texto para poder comenzar con el vaciado de datos.

    //Se comienza con el analisis de los paquetes, para este punto el método main se vuelve el Capturador
    for(int i = 0; i < packets; i++){
        char * buffer = (char *) calloc(2000, sizeof(char)); //Se reserva memoria para obtener los datos de los paquetes entrantes
        EthernetCustom * ethernetCustom = (EthernetCustom * ) malloc(sizeof(EthernetCustom)); //Se Reserva memoria para poder configurar los datos de los paquetes
        ethernetCustom->size = recvfrom(sock, buffer, 2000, 0, &saddr, &size_saddr);//Se recibe un paquete

        struct ethhdr * ethernet; //Estructura que permite almacenar los datos de los paquetes
        ethernet = (struct ethhdr * ) buffer; //Casteo del buffer
        ethernetCustom->ethernet = ethernet;  //Se almacena la variable en nuestra estructura
        
        /*Se crea un proceso hijo para analizar los paquetes pasando como parametro nuestra estructura creada*/
        if(pthread_create(&anlzr[i], NULL, analizer, (void * )ethernetCustom)){
            printf("\nProblemas creando el hilo del analizador\n");
            exit(EXIT_FAILURE);
        };

    }

    /*Se esperan a que todos los procesos hijos terminen*/
    for(int i = 0; i < packets; i++){ 
        if(pthread_join(anlzr[i], &valor_retorno)){
            printf("\nProblemas creando el enlace\n");
            exit(EXIT_FAILURE);
        };
    }

    /*Se imprime en pantalla y en el archivo de texto nuestro Resumen*/
    printf("\n------------------Resumen de analisis-------------------------\n");
    fprintf(fp,"\n------------------Resumen de analisis-------------------------\n");
    printf("\nTramas IEEE 802.3 analizadas: %i, Tramas Ethernet II analizadas %i\n", analisis->ieee802_3, analisis->ethh2);
    fprintf(fp, "\nTramas IEEE 802.3 analizadas: %i, Tramas Ethernet II analizadas %i\n", analisis->ieee802_3, analisis->ethh2);
    printf("\nTramas de protocolo de capa superior\n");
    fprintf(fp,"\nTramas de protocolo de capa superior\n");

    printf("\nIPv4: %i paquetes\n", analisis->ipv4);
    printf("\nIPv6: %i paquetes\n", analisis->ipv6);
    printf("\nARP: %i paquetes\n", analisis->arp);
    printf("\nControl de Flujo de Ethernet: %i paquetes\n", analisis->ethh_stream_control);
    printf("\nSeguridad MAC: %i paquetes\n", analisis->mac_security);

    fprintf(fp,"\nIPv4: %i paquetes\n", analisis->ipv4);
    fprintf(fp,"\nIPv6: %i paquetes\n", analisis->ipv6);
    fprintf(fp,"\nARP: %i paquetes\n", analisis->arp);
    fprintf(fp,"\nControl de Flujo de Ethernet: %i paquetes\n", analisis->ethh_stream_control);
    fprintf(fp,"\nSeguridad MAC: %i paquetes\n", analisis->mac_security);

    deactivatePromiscMode(cardInterface);  //Se reestablecen los valores originales de la NIC
    desplegarInformacion(nodo,fp); //Se despliega la información del listado de MACs
    
    /*Se libera la memoria*/
    free(nodo);
    free(analisis);
    fclose(fp);

    return 0;

}

void *analizer(void * data){

    EthernetCustom * ethernetCustom = (EthernetCustom * ) data; //Se recupera la data enviada por el proceso padre
    int j = 0; //Variable para poder iterar sobre los datos de la MAC

        if(htons(ethernetCustom->ethernet->h_proto) >= 0x600 ){//Se verifica que el protocolo es de Ethernet II

            /*Se verifica en la lista y agrega o actualiza en la lista los valores de los listados de las MAC*/
            if(actualizarMasUno(nodo, ethernetCustom->ethernet->h_dest) == 0){
                nodo = insertarFinal(ethernetCustom->ethernet->h_dest, 1, nodo);
            }
            
            /*Se despliega que tipo de protocolo es en su valor hexadecimal*/
            printf("\nTipo: 0x%.4X", ethernetCustom->ethernet->h_proto);
            fprintf(fp,"\nTipo: 0x%.4X", ethernetCustom->ethernet->h_proto);

            clasifyProtocol(ethernetCustom->ethernet->h_proto); //Se clasifica que protocolo es

            /*Se imprime la MAC de Origen*/
            printf("\tOrigen: ");
            fprintf(fp, "\tOrigen: ");
            for(j = 0 ; j < 6; j++){
                printf("%2X", ethernetCustom->ethernet->h_source[j]);
                fprintf(fp,"%2X", ethernetCustom->ethernet->h_source[j]);

                if(j != 5){
                    printf(":");
                    fprintf(fp,":");
                }
            }
            /*Se imprime la mac de destino*/
            printf("\tDestino: ");
            fprintf(fp,"\tDestino: ");

            for(j = 0 ; j < 6; j++){
                printf("%2X", ethernetCustom->ethernet->h_dest[j]);
                fprintf(fp,"%2X", ethernetCustom->ethernet->h_dest[j]);

                if(j != 5){
                    printf(":");
                    fprintf(fp,":");
                }
            }

            analisis->ethh2++;//Se incrementa el contador de trama de Ethernet II
            /*Se imprime la longitud de la trama así como la longitud de carga útil*/
            printf("\tLongitud de la trama: %i, Longitud de carga útil: %i\n",ethernetCustom->size, ethernetCustom->size-14);
            fprintf(fp,"\tLongitud de la trama: %i, Longitud de carga útil: %i",ethernetCustom->size, ethernetCustom->size-14);
            clasifyDifusion(ethernetCustom->ethernet->h_dest[0]);/*Se hace la clasificación de la difusión*/
        }
        else{
            analisis->ieee802_3++;//Se incrementa el contador de paquetes de tipo IEEE 802.3
            printf("\nTrama no analizada\n");
            fprintf(fp,"\nTrama no analizada\n");
        }

        free(ethernetCustom); //Se libera la memoria
}

void clasifyDifusion(unsigned char d){

    /*Se imprime que tipo de difusión tiene la memoria*/
    switch(d){
        case 255:{//FF
            printf(" Difusion\n");
            fprintf(fp, " Difusion\n");
        }
        break;
        case 0:{
            printf(" Unidifusion\n");
            fprintf(fp, " Unidifusion\n");
        }
        break;
        case 1:{//01
            printf(" Multifusion\n");
            fprintf(fp, " Multifusion\n");
        }
        break;
        default:{
            printf(" Ninguna difusion");
            fprintf(fp, " Ninguna difusion\n");
        }
        break;
    }

}

void deactivatePromiscMode(char * card_interface){

    char * command = (char *) calloc(100, sizeof(char));

    strcpy(command, "/sbin/ifconfig ");
    strcat(command, card_interface);
    strcat(command, " -promisc");

    system(command);

    free(command);
}

void clasifyProtocol(unsigned short d){
    //Se imprime que timpo de protocolo es la trama
    switch(htons(d)){
        case 0x0800:{
            printf("\tIPv4");
            fprintf(fp, "\tIPv4");
            analisis->ipv4++;
        }
        break;
        case 0x86DD:{
            printf("\tIPv6");
            fprintf(fp, "\tIPv6");
            analisis->ipv6++;
        }
        break;
        case 0x0806:{
            printf("\tARP");
            fprintf(fp, "\tARP");
            analisis->arp++;
        }
        break;
        case 0x8808:{
            printf("\tStream Control Ethernet");
            fprintf(fp, "\tStream Control Ethernet");
            analisis->ethh_stream_control++;
        }
        break;
        case 0x88E5:{
            printf("\tMAC Security");
            fprintf(fp, "\tMAC Security");
            analisis->mac_security++;
        }
        break;
        default:{
            
        }
        
    }

}