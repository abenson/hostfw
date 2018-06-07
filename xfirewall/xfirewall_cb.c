#include <stdlib.h>

#include "xfirewall.h"
#include "common.h"

extern FD_xfirewall *fd_xfirewall;

/* Callbacks and freeobj handlers for form xfirewall */


/***************************************
 ***************************************/

void
outbound_tcp_cb( FL_OBJECT * obj,
                 long        data )
{
    if(fl_get_button(obj)) {
        xf_activate(fd_xfirewall->outbound_tcp_list);
    } else {
        xf_deactivate(fd_xfirewall->outbound_tcp_list);
    }
}


/***************************************
 ***************************************/

void
outbound_udp_cb( FL_OBJECT * obj,
                 long        data )
{
    if(fl_get_button(obj)) {
        xf_activate(fd_xfirewall->outbound_udp_list);
    } else {
        xf_deactivate(fd_xfirewall->outbound_udp_list);
    }
}


/***************************************
 ***************************************/

void
outbound_tcp_list_cb( FL_OBJECT * obj,
                      long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
outbound_udp_list_cb( FL_OBJECT * obj,
                      long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
inbound_tcp_cb( FL_OBJECT * obj,
                long        data )
{
    if(fl_get_button(obj)) {
        xf_activate(fd_xfirewall->inbound_tcp_list);
    } else {
        xf_deactivate(fd_xfirewall->inbound_tcp_list);
    }}


/***************************************
 ***************************************/

void
inbound_tcp_list_cb( FL_OBJECT * obj,
                     long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
inbound_udp_cb( FL_OBJECT * obj,
                long        data )
{
    if(fl_get_button(obj)) {
        xf_activate(fd_xfirewall->inbound_udp_list);
    } else {
        xf_deactivate(fd_xfirewall->inbound_udp_list);
    }
}


/***************************************
 ***************************************/

void
inbound_udp_list_cb( FL_OBJECT * obj,
                     long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
autotrust_cb( FL_OBJECT * obj,
              long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
default_rules_cb( FL_OBJECT * obj,
                  long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
allow_all_cb( FL_OBJECT * obj,
              long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
deny_all_cb( FL_OBJECT * obj,
             long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
cancel_cb( FL_OBJECT * obj,
           long        data )
{
    exit(EXIT_SUCCESS);
}


/***************************************
 ***************************************/

void
accept_cb( FL_OBJECT * obj,
           long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
outbound_hosts_cb( FL_OBJECT * obj,
                   long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
outbound_load_file_cb( FL_OBJECT * obj,
                       long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
outbound_enter_manually_cb( FL_OBJECT * obj,
                            long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
inbound_hosts_cb( FL_OBJECT * obj,
                  long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
inbound_load_file_cb( FL_OBJECT * obj,
                      long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
inbound_enter_manually_cb( FL_OBJECT * obj,
                           long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
deny_hosts_cb( FL_OBJECT * obj,
               long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
deny_load_file_cb( FL_OBJECT * obj,
                   long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
deny_enter_manually_cb( FL_OBJECT * obj,
                        long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
send_resets_cb( FL_OBJECT * obj,
                long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
dont_restrict_icmp_cb( FL_OBJECT * obj,
                       long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
dont_allow_dhcp_cb( FL_OBJECT * obj,
                    long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
log_exceptions_cb( FL_OBJECT * obj,
                   long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
simulate_only_cb( FL_OBJECT * obj,
                  long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
show_status_cb( FL_OBJECT * obj,
                long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
show_rules_cb( FL_OBJECT * obj,
               long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
save_script_cb( FL_OBJECT * obj,
                long        data )
{
    /* Fill-in code for callback here */
}


/***************************************
 ***************************************/

void
save_file_picker_cb( FL_OBJECT * obj,
                     long        data )
{
       const char *filename;
       filename = fl_show_fselector("Name of the saved script",
                                    ".",
                                "*.sh",
                                "firewall.sh");
       fl_set_input(fd_xfirewall->save_file_name, filename);
}




