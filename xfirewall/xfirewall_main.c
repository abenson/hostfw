#include "xfirewall.h"

FD_xfirewall *fd_xfirewall;

/***************************************
 ***************************************/

void
xf_set_initial( void )
{
	FD_xfirewall *xf = fd_xfirewall;

	/* port input lists */
	fl_deactivate_object(xf->outbound_tcp_list);
	fl_deactivate_object(xf->outbound_udp_list);
	fl_deactivate_object(xf->inbound_tcp_list);
	fl_deactivate_object(xf->inbound_udp_list);

	/* host input buttons */
	fl_deactivate_object(xf->outbound_load_file);
	fl_deactivate_object(xf->outbound_enter_manually);
	fl_deactivate_object(xf->inbound_load_file);
	fl_deactivate_object(xf->inbound_enter_manually);
	fl_deactivate_object(xf->deny_load_file);
	fl_deactivate_object(xf->deny_enter_manually);

	fl_deactivate_object(xf->save_file_name);
}

/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    fl_initialize( &argc, argv, 0, 0, 0 );
    fd_xfirewall = create_form_xfirewall( );

    /* Fill-in form initialization code */

    xf_set_initial();

    /* Show the first form */

    fl_show_form( fd_xfirewall->xfirewall, FL_PLACE_CENTER, FL_FULLBORDER, "xfirewall" );

    fl_do_forms( );

    if ( fl_form_is_visible( fd_xfirewall->xfirewall ) )
        fl_hide_form( fd_xfirewall->xfirewall );
    fl_free( fd_xfirewall );
    fl_finish( );

    return 0;
}
