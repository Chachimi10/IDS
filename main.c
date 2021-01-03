#include "populate.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

struct ids_rule
{
        char *action;
        char *protocol;
        char *source_ip;
        char *source_port;
        char *in_out;
        char *destination_ip;
        char *destination_port;
        char *options;
        char *options2;
        struct Rule *next;

} typedef Rule;

Rule *first = NULL; Rule *last = NULL;

void rule_matcher(Rule *rules_ds, ETHER_Frame *frame)
{

        char *pack_protocol;
        char pack_sport[5];
        char pack_dport[5];
        

        printf("------------------\n");
        printf("Infos Packet Reçu : \n");
        printf("------------------\n");
        // Protocol
        pack_protocol = " ";

        

        if(frame->data.protocol == TCP_PROTOCOL){

                pack_protocol = "tcp";
                snprintf(pack_sport, 5, "%d", frame->data.data_tcp.source_port);
                snprintf(pack_dport, 5, "%d", frame->data.data_tcp.destination_port);
                

                printf("\nProtocol : TCP\n");
                printf("\n Source Port TCP : %d \n", frame->data.data_tcp.source_port);
                printf("\nDestination Port TCP : %d \n", frame->data.data_tcp.destination_port);

               
        
        }
        if(frame->data.protocol == UDP_PROTOCOL){

                pack_protocol = "udp";
                snprintf(pack_sport, 5, "%d", frame->data.data_udp.source_port);
                snprintf(pack_dport, 5, "%d", frame->data.data_udp.destination_port);
               

                printf("\nProtocol : UDP\n");
                printf("\nSource Port UDP : %d \n", frame->data.data_udp.source_port);
                printf("\nDestination Port UDP : %d \n", frame->data.data_udp.destination_port);


                
        }
        
        printf("\nSource IP : %s \n", frame->data.source_ip);
        printf("\nDestination IP : %s \n", frame->data.destination_ip);



        rules_ds = first;


        while(rules_ds != NULL){
                
                              

                if(strcmp(rules_ds->protocol, pack_protocol) == 0){

                        if( (strcmp(rules_ds->source_ip, "any") == 0) || (strcmp(rules_ds->source_ip, frame->data.source_ip) == 0) ){
                                
                                if((strcmp(rules_ds->source_port, "any") == 0) || (strcmp(rules_ds->source_port, pack_sport) == 0)){
                                        
                                        if((strcmp(rules_ds->destination_ip, "any") == 0)|| (strcmp(rules_ds->destination_ip, frame->data.destination_ip) == 0)){
                                                
                                                if( (strcmp(rules_ds->destination_port, "any") == 0) || (strcmp(rules_ds->destination_port, pack_dport) == 0)){
                                                        const char *content_option = rules_ds->options;
                                                        const char *content_option2 = rules_ds->options2;
                                                        const char *delimiter = "\"";
                                                        char *report_syslog = NULL;
                                                        char *alert_http = NULL;
                                                        char *start, *end;

                                                        if ( start = strstr( content_option2, delimiter ) )
                                                        {
                                                                start += strlen( delimiter );
                                                                if ( end = strstr( start, delimiter ) )
                                                                {
                                                                alert_http = ( char * )malloc( end - start + 1 );
                                                                memcpy( alert_http, start, end - start );
                                                                alert_http[end - start] = '\0';


                                                                printf("=> Malware.exe");
                                                                printf("%s", alert_http);
                                                                }
                                                                return 0;
                                                        }


                                                        /*if ( start = strstr( content_option, delimiter ) )
                                                        {
                                                                start += strlen( delimiter );
                                                                if ( end = strstr( start, delimiter ) )
                                                                {
                                                                report_syslog = ( char * )malloc( end - start + 1 );
                                                                memcpy( report_syslog, start, end - start );
                                                                report_syslog[end - start] = '\0';
                                                                }
                                                                
                                                        }*/

                                                        
                                                        printf("%s\n", report_syslog);
                                                        openlog("IR209", LOG_PID|LOG_CONS, LOG_USER);
                                                        syslog(LOG_INFO, report_syslog);
                                                        closelog();
                                                }
                                        }
                                }
                                
                        }
                }
                //printf("%s | %s | %s | %s | %s | %s | %s | %s \n", rules_ds->action, rules_ds->protocol, rules_ds->source_ip, rules_ds->source_port, rules_ds->in_out, rules_ds->destination_ip, rules_ds->destination_port, rules_ds->options);
                rules_ds = rules_ds->next;
        } 

        


        printf("------------------\n");

        
}


void read_rules(FILE *file, Rule *rules_ds, int count)
{
        char line[200];

        char action[100];
        char protocol[100];
        char source_ip[100];
        char source_port[100];
        char in_out[100];
        char destination_ip[100];
        char destination_port[100];
        char options[400];
        char options2[400];


        while (fgets (line, sizeof(line), file)){
            rules_ds = malloc(sizeof(Rule)); 
            
            if(sscanf(line, "%s %s %s %s %s %s %s %s %s", action, protocol, source_ip, source_port, in_out, destination_ip, destination_port, options, options2 )!= 9){

                    if(sscanf(line, "%s %s %s %s %s %s %s %s", action, protocol, source_ip, source_port, in_out, destination_ip, destination_port, options)!= 8){
                      
                      return 1;
                    } else {
                            rules_ds->options2 = NULL;
                    }
            } else {
                rules_ds->options2 = strdup(options2);  
            }
            

            

            rules_ds->action = strdup(action);
            rules_ds->protocol = strdup(protocol);
            rules_ds->source_ip = strdup(source_ip);
            rules_ds->source_port = strdup(source_port);
            rules_ds->in_out = strdup(in_out);
            rules_ds->destination_ip = strdup(destination_ip);
            rules_ds->destination_port = strdup(destination_port);
            rules_ds->options = strdup(options);
            
            rules_ds->next = NULL;

            if (first == NULL) {
                first = rules_ds;
                last = rules_ds;
            } else {
                last->next = rules_ds;
                last = rules_ds;
            } 

        }

        rules_ds = first; 

}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
        
        ETHER_Frame custom_frame;
        populate_packet_ds(header, packet, &custom_frame);
        rule_matcher(first, &custom_frame);
}

int main(int argc, char *argv[]) 
{
        // Carte réseau à lire
        char *device = "eth0";

        // Fichier avec les règles à lire
        char *file_name = argv[1];
        // Verb du fichier lû
        printf("\n Chemin du fichier de règle : %s", file_name);

        // Initialisation Lecture fichier règle
        FILE *file = fopen(file_name, "r");
        

        if(file == NULL){

                printf("\n Le fichier est introuvable : %s", file_name);
                return 0;
        }

        // Comptable Nb de règles

        char c;

        int count_line = 0;

        for (c = getc(file); c != EOF; c = getc(file))
                if (c == '\n')
                        count_line = count_line + 1;


        printf("\n Il y a %d règles.", count_line+1);

        fclose(file);

        // Lecture des règles

        FILE *file2 = fopen(file_name, "r");
        Rule *rules_ds = NULL;

        read_rules(file2, rules_ds, count_line);

        fclose(file2);

        // Affichage des règles

        rules_ds = first;


        printf("\n\n Règlee(s) chargée(s) :  \n");
        printf("\n Action | type | IP Source | Port Source | Directon | IP Dest | Port Dest | Options \n");
        while(rules_ds != NULL){
                printf("%s | %s | %s | %s | %s | %s | %s | %s | %s\n", rules_ds->action, rules_ds->protocol, rules_ds->source_ip, rules_ds->source_port, rules_ds->in_out, rules_ds->destination_ip, rules_ds->destination_port, rules_ds->options, rules_ds->options2);
                rules_ds = rules_ds->next;
        }  

        rules_ds = first;
      

        // Scan des packets     

        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *handle;

        handle = pcap_create(device,error_buffer);
        pcap_set_timeout(handle,100);
        pcap_activate(handle);
        int total_packet_count = 100;

        pcap_loop(handle, total_packet_count, my_packet_handler, NULL);

        return 0;

        
}