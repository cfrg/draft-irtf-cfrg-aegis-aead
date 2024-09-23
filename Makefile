LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
	cd $(LIBDIR) ; git reset --hard 414003950dfd8d951bbf5a130f9aae354dfda91c ; cd -
endif
