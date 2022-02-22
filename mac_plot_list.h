#ifndef _MAC_PLOT_LIST_
#define _MAC_PLOT_LIST_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
    Estructura de datos de lista para almacenar y clasificar las macs así como las tramas que les pertenecen.
*/

typedef struct _Nodo{
    unsigned char mac[6];
    int num_plot;
    struct _Nodo *sig;
    struct _Nodo *anterior;
} Nodo;

Nodo * crear(unsigned char * ma, int np){

    Nodo * nuevo;

    nuevo = (Nodo *) malloc(sizeof(Nodo));
    nuevo->num_plot = np;

    for(int i = 0; i < 6; i++){
        nuevo->mac[i]= ma[i];
    }
    
    nuevo->sig= NULL;

    return nuevo;

}

int detNumElem(Nodo * inicio){
    int num = 0;
    
    if(inicio == NULL){
        num = 0;
    }
    else{
        while(inicio != NULL){
            num++;
            inicio = inicio->sig;
        }
    }

    return num;
}

Nodo * insertarFinal(unsigned char * ma, int np, Nodo *inicio){
    Nodo * nuevo;
    Nodo * aux;
    nuevo = crear(ma, np);

    if(inicio == NULL){
        inicio = nuevo;
    }else{
        aux = inicio;
        while(aux->sig != NULL){
            aux = aux ->sig;
        }

        nuevo->anterior = aux;
        aux->sig = nuevo;
    }

    return inicio;
}

/*
    Método para incrementar de uno en uno los paquetes por dirección MAC.
*/

int actualizarMasUno(Nodo * inicio, unsigned char * llave){
    Nodo * aux = inicio;
    int i = 0;
    int longitudLista = detNumElem(inicio);
    int validador = 0;
    while(longitudLista != 0){
        for(int i = 0; i < 6; i++){
            if(aux->mac[i] == llave[i]){
                validador = 1;
            }
            else{
                validador = 0;
                break;
            }
        }

        if(validador == 1){
            aux->num_plot = aux->num_plot + 1;
            break;
        }

        aux = aux->sig;
        longitudLista--;

    }

    if(longitudLista == 0){
        return 0;
    }
    else if(validador == 1){
        return 1;
    }
}

/*
    Aquí se despliega la información de la lista.
*/

void desplegarInformacion(Nodo *inicio, FILE * fp){
    if(inicio == NULL){
        printf("La lista esta vacía");
    }
    else{
        while(inicio != NULL){
            int i = 0;
            printf("\nDestino: ");
            fprintf(fp, "\nDestino: ");
            for(i = 0; i < 6; i++){
                printf("%2X", inicio->mac[i]);
                fprintf(fp,"%2X", inicio->mac[i]);

                if(i != 5){
                    printf(":");
                    fprintf(fp,":");
                }
            }

            printf("\t Tramas: %i\n", inicio->num_plot);
            fprintf(fp,"\t Tramas: %i\n", inicio->num_plot);
            inicio = inicio->sig;
        }
    }
}



#endif // MAC_PLOT_LIST_