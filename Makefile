LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
	cd $(LIBDIR) ; git reset --hard f0e1f77fd221baf39d5eb46d45440d40db975de2 ; cd -
endif
