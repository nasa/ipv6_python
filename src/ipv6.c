/* Advanced IPv6 Socket Manipulation for Python
 *
 * Copyright © 2015 United States Government as represented by Joseph Ishac.
 * No copyright is claimed in the United States under Title 17, U.S.Code.
 * All Other Rights Reserved.
 *
 */
//#define __UAPI_DEF_IPV6_OPTIONS 1
#define IPV6_FLOWLABEL_MGR  32
#define IPV6_FLOWINFO_SEND  33

#include "Python.h"
#include "structmember.h"
#include <math.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/in6.h>
#include <arpa/inet.h>

/* static PyObject *err; */

typedef struct {
  PyObject_HEAD
} IPV6;

long create_flow_label (int, struct sockaddr_in6 *);

/* destructor */
static void
IPV6_dealloc(IPV6* self)
{
  // Free the object itself
  self->ob_type->tp_free((PyObject*)self);
}

/* constructor */
static PyObject *
IPV6_new(PyTypeObject *type, PyObject *args)
{
  IPV6 *self;

  // REFCOUNT NOTE: Call auto adds reference, macro Py_INCREF not needed
  self = (IPV6 *)type->tp_alloc(type, 0);
  if (self != NULL) 
  {
    return (PyObject *)self;
  }
  return PyErr_NoMemory();
}

/*  initialize */
static PyObject *
IPV6_init(IPV6 *self)
{
  Py_RETURN_NONE;
}

/* declare members to python */
// Nothing to declare
static PyMemberDef IPV6_members[] = {
    {NULL} /* Sentinel */
};

/* * * * * * * * * * * * * * Methods * * * * * * * * * * * * * */

/* get_flow_label - This method gets a random flow label from the kernel and
 * also turns on flow labels for a given Python socket or socket file descriptor
 * (the latter may only be possible in Linux).  It returns a new Python
 * four-tuple (host, port, flowinfo, scopeid) address for AF_INET6 address
 * family. The flowinfo part of this tuple will have been updated with the flow
 * label obtained from the kernel. The user may supply the initial AF_INET6
 * address when making this method call.
 * 
 * For Example:
 *   import ipv6
 *   # Set-up a IPv6 Socket ...
 *   sockaddr = ipv6.get_flow_label(sock,*sockaddr)
 */
static PyObject *
get_flow_label (IPV6 *self, PyObject *args)
{
  PyObject *socket;
  int sock;
  socklen_t len;
  struct sockaddr_storage addr;
  struct sockaddr_in6 *addr_in6;
  PyObject *answer;
  long result = 0;
  char msg[300];
  char v6dst[INET6_ADDRSTRLEN]="::1";
  char *ptr;
  int  v6port=-1;
  long v6flow=0;
  int  v6scope=0;
  int debug_family;

// FOR REFERENCE:
// struct sockaddr_in6 {
//     sa_family_t     sin6_family;   /* AF_INET6 */
//     in_port_t       sin6_port;     /* port number */
//     uint32_t        sin6_flowinfo; /* IPv6 flow information */
//     struct in6_addr sin6_addr;     /* IPv6 address */
//     uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
// };
// 
// struct in6_addr {
//     unsigned char   s6_addr[16];   /* IPv6 address */
// };

  if ((! PyArg_ParseTuple(args, "O|sili", &socket, &ptr, &v6port, &v6flow, &v6scope)))
  {
    PyErr_SetString(PyExc_ValueError, "Malformed Request! Required: (Socket Object or Socket FD), Optional: (Host, Port, FlowInfo, Scope)");
    return NULL;
  }
  strncpy (v6dst, ptr, sizeof(v6dst) );

  if (PyInt_Check(socket))
  {
    // Assume they passed the Socket File Descriptor
    sock = (int) PyInt_AsLong(socket);
    if (sock == -1)
    {
      PyErr_SetString(PyExc_RuntimeError, "Unable to Convert Socket Descriptor!");
      return NULL;
    }
  } else {
    // If we were passed a socket we might need to do this...
    answer = PyObject_CallMethod(socket,"fileno",NULL);
    if (answer == NULL)
    {
      PyErr_SetString(PyExc_RuntimeError, "Bad Socket Descriptor!");
      Py_DECREF(answer);
      return NULL;
    }
    if (PyInt_Check(answer))
    {
      sock = (int) PyInt_AsLong(answer);
      if (sock == -1)
      {
        PyErr_SetString(PyExc_RuntimeError, "Unable to Convert Socket Descriptor!");
        Py_DECREF(answer);
        return NULL;
      }
    } else {
      PyErr_SetString(PyExc_RuntimeError, "Bad Answer from Fileno!");
      Py_DECREF(answer);
      return NULL;
    }
    Py_DECREF(answer);
  }

  len = sizeof addr;
  getpeername(sock, (struct sockaddr *)&addr, &len);
  // Only care about IPv6
  if (addr.ss_family != AF_INET)
  {
    debug_family = addr.ss_family;
    addr_in6 = (struct sockaddr_in6*)&addr;
  } else {
    PyErr_SetString(PyExc_RuntimeError, "Passed a Non-IPv6 Socket!");
    return NULL;
  }

  if (addr_in6->sin6_family != AF_INET6) {
    // Perhaps we are not connected - either used supplied info or get local info?
    // Get local info
    getsockname(sock, (struct sockaddr *)&addr, &len);
    if (addr.ss_family != AF_INET)
    {
      debug_family = addr.ss_family;
      addr_in6 = (struct sockaddr_in6*)&addr;
    } else {
      PyErr_SetString(PyExc_RuntimeError, "Passed a Non-IPv6 Local Socket!");
      return NULL;
    }
    // Info Supplied if port > 0
    if (v6port > 0)
    {
      addr_in6->sin6_port = htons(v6port);
      inet_pton(AF_INET6, v6dst, &(addr_in6->sin6_addr));
      addr_in6->sin6_flowinfo = htonl(v6flow);
      addr_in6->sin6_scope_id = v6scope;
    }
  }
  if (addr_in6->sin6_family != AF_INET6) {
    snprintf(msg,sizeof(msg),"Unexpected Error! Sock (%d): [%d, %d], %d, %d, %d, %d",sock,AF_INET6,debug_family,addr_in6->sin6_family,ntohs(addr_in6->sin6_port),addr_in6->sin6_flowinfo,addr_in6->sin6_scope_id);
    PyErr_SetString(PyExc_RuntimeError, msg);
    return NULL;
  }
  
  inet_ntop(AF_INET6, &(addr_in6->sin6_addr), v6dst, INET6_ADDRSTRLEN);
  result = create_flow_label(sock,addr_in6);
  if (result == -1)
  {
    // Creation Failed!!
    return NULL;
  }
  v6port = ntohs(addr_in6->sin6_port);
  v6flow = ntohl(result);
  return(Py_BuildValue("(sili)",v6dst,v6port,v6flow,v6scope));
}


// FOR REFERENCE:
// struct in6_flowlabel_req
// {
//   struct in6_addr flr_dst;
//   __u32 flr_label;
//   __u8 flr_action;
//   __u8 flr_share;
//   __u16 flr_flags;
//   __u16 flr_expires;
//   __u16 flr_linger;
//   __u32 __flr_pad;
// };

long
create_flow_label (int sock, struct sockaddr_in6 *addr)
{
  struct in6_flowlabel_req flr;
  int on = 1;
  char msg[300];
  
  //flr.flr_label = addr->sin6_flowinfo;
  flr.flr_label = 0;
  flr.flr_action = IPV6_FL_A_GET;
  flr.flr_flags = IPV6_FL_F_CREATE;
  flr.flr_share = IPV6_FL_S_EXCL;
  flr.flr_dst = addr->sin6_addr;
  flr.flr_expires = 0;
  flr.flr_linger = 0;
  flr.__flr_pad = 0;

  if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, &flr, sizeof(flr)) == -1)
  {
    snprintf(msg,sizeof(msg),"Failed to set flow label: %s",strerror(errno));
    PyErr_SetString(PyExc_RuntimeError, msg);
    return -1;
  }
  if (setsockopt(sock, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof(on)) == -1)
  {
    snprintf(msg,sizeof(msg),"Unable to enable flow labels: %s",strerror(errno));
    PyErr_SetString(PyExc_RuntimeError, msg);
    return -1;
  }
  addr->sin6_flowinfo=flr.flr_label;
  return flr.flr_label;
}

/* deslare methods to python */
static PyMethodDef IPV6_methods[] = {
    {"get_flow_label", (PyCFunction)get_flow_label, METH_VARARGS, 
        "Get and use a random flow label from the kernel."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

/* number object operators */
static PyNumberMethods IPV6Operators = {
    0,                                           /* nb_add */
    0,                                           /* nb_subtract */
    0,                                           /* nb_multiply */
    0,                                           /* nb_divide */
    0,                                           /* nb_remainder */
    0,                                           /* nb_divmod */
    0,                                           /* nb_power */
    0,                                           /* nb_negative */
    0,                                           /* nb_positive */
    0,                                           /* nb_absolute */
    0,                                           /* nb_nonzero / nb_bool */
    0,                                           /* nb_invert */
    0,                                           /* nb_lshift */
    0,                                           /* nb_rshift */
    0,                                           /* nb_and */
    0,                                           /* nb_xor */
    0,                                           /* nb_or */
    0,                                           /* nb_coerce */
    0,                                           /* nb_int */
    0,                                           /* nb_long */
    0,                                           /* nb_float */
    0,                                           /* nb_oct */
    0,                                           /* nb_hex */
    0,                                           /* nb_inplace_add */
    0,                                           /* nb_inplace_subtract */
    0,                                           /* nb_inplace_multiply */
    0,                                           /* nb_inplace_divide */
    0,                                           /* nb_inplace_remainder */
    0,                                           /* nb_inplace_power */
    0,                                           /* nb_inplace_lshift */
    0,                                           /* nb_inplace_rshift */
    0,                                           /* nb_inplace_and */
    0,                                           /* nb_inplace_xor */
    0,                                           /* nb_inplace_or */
    0,                                           /* nb_floor_divide */
    0,                                           /* nb_true_divide */
    0,                                           /* nb_inplace_floor_divide */
    0,                                           /* nb_inplace_true_divide */
    0,                                           /* nb_index */
};

static PyTypeObject IPV6Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "ipv6.IPV6",               /*tp_name*/
    sizeof(IPV6),              /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)IPV6_dealloc,  /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    &IPV6Operators,            /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_CHECKTYPES,
    "IPV6 Object",             /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    IPV6_methods,              /* tp_methods */
    IPV6_members,              /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)IPV6_init,       /* tp_init */
    0,                         /* tp_alloc */
    (void *)IPV6_new,          /* tp_new */
};

static PyMethodDef module_methods[] = {
    {"get_flow_label", (PyCFunction)get_flow_label, METH_VARARGS, 
        "Get and use a random flow label from the kernel."},
    {NULL, NULL, 0, NULL} /* Sentinel */
};

#ifndef PyMODINIT_FUNC  /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initipv6(void) 
{
    PyObject* m;

    if (PyType_Ready(&IPV6Type) < 0)
        return;

    m = Py_InitModule3("ipv6", module_methods,
                       "IPV6 Object base type.");

    if (m == NULL)
        return;

    Py_INCREF(&IPV6Type);
    PyModule_AddObject(m, "IPV6", 
        (PyObject *)&IPV6Type);
}

