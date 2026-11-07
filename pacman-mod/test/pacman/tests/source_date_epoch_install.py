self.description = "Check that installing a package retains INSTALL DATE with SOURCE_DATE_EPOCH"

p = pmpkg("pkg1")
p.files = ["foo/file1",
           "foo/file2"]
self.addpkg(p)

self.args = "-U %s" % p.filename()
self.env = {"SOURCE_DATE_EPOCH": "1662046009"}

self.addrule("PACMAN_RETCODE=0")
self.addrule("PKG_INSTALLDATE=pkg1|1662046009")
