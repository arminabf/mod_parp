APACHE_MODPATH_INIT(parp)

APACHE_MODULE(parp, parp, , , shared)
APACHE_MODULE(parp_appl, parp test application, , , shared)

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH

