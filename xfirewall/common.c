#include <forms.h>

#include "xfirewall.h"
#include "common.h"

extern FD_xfirewall *fd_xfirewall;

void xf_deactivate(FL_OBJECT *obj)
{
	fl_deactivate_object(obj);
	fl_set_object_color(obj, FL_INACTIVE, FL_MCOL);
}

void xf_activate(FL_OBJECT *obj)
{
	fl_activate_object(obj);
	fl_set_object_color(obj, FL_COL1, FL_MCOL);
}
