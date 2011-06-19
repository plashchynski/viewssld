DOCS = manual.pdf
dist_man8_MANS = viewssld.8
EXTRA_DIST = viewssld.conf $(DOCS)

install-data-local:
	test -z "/etc/viewssld.conf" || $(INSTALL) -m 600 examples/viewssld.conf /etc/viewssld.conf

