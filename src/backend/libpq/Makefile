#-------------------------------------------------------------------------
#
# Makefile--
#    Makefile for libpq subsystem (backend half of libpq interface)
#
# IDENTIFICATION
#    src/backend/libpq/Makefile
#
#-------------------------------------------------------------------------

subdir = src/backend/libpq
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

# be-fsstubs is here for historical reasons, probably belongs elsewhere

OBJS = \
	auth-oauth.o \
	auth-sasl.o \
	auth-scram.o \
	auth.o \
	be-fsstubs.o \
	be-secure-common.o \
	be-secure.o \
	crypt.o \
	hba.o \
	ifaddr.o \
	pqcomm.o \
	pqformat.o \
	pqmq.o \
	pqsignal.o

ifeq ($(with_ssl),openssl)
OBJS += be-secure-openssl.o
endif

# The LIN authentication method needs libcurl to reach its REST API
ifeq ($(with_libcurl),yes)
OBJS += auth-lin.o
override CPPFLAGS += $(LIBCURL_CPPFLAGS)
endif

ifeq ($(with_gssapi),yes)
OBJS += be-gssapi-common.o be-secure-gssapi.o
endif

include $(top_srcdir)/src/backend/common.mk
