#include "xfirewall.h"
#include "common.h"

FD_xfirewall *fd_xfirewall;

/***************************************
 ***************************************/

void
xf_set_initial( void )
{
	FD_xfirewall *xf = fd_xfirewall;

	/* port input lists */
	xf_deactivate(xf->outbound_tcp_list);
	xf_deactivate(xf->outbound_udp_list);
	xf_deactivate(xf->inbound_tcp_list);
	xf_deactivate(xf->inbound_udp_list);

	/* host input buttons */
	xf_deactivate(xf->outbound_load_file);
	xf_deactivate(xf->outbound_enter_manually);
	xf_deactivate(xf->inbound_load_file);
	xf_deactivate(xf->inbound_enter_manually);
	xf_deactivate(xf->deny_load_file);
	xf_deactivate(xf->deny_enter_manually);

	/* file picker */
	xf_deactivate(xf->save_file_name);
	xf_deactivate(xf->save_file_picker);
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
