#include "xfirewall.h"


/***************************************
 ***************************************/

int
main( int    argc,
      char * argv[ ] )
{
    FD_xfirewall *fd_xfirewall;

    fl_initialize( &argc, argv, 0, 0, 0 );
    fd_xfirewall = create_form_xfirewall( );

    /* Fill-in form initialization code */

    /* Show the first form */

    fl_show_form( fd_xfirewall->xfirewall, FL_PLACE_CENTER, FL_FULLBORDER, "xfirewall" );

    fl_do_forms( );

    if ( fl_form_is_visible( fd_xfirewall->xfirewall ) )
        fl_hide_form( fd_xfirewall->xfirewall );
    fl_free( fd_xfirewall );
    fl_finish( );

    return 0;
}
