#ifndef __MSG_X_H
#define __MSG_X_H

#include <sys/types.h>
#include <sys/socket.h>

/*
 * Extended version for sendmsg_x() and recvmsg_x() calls
 *
 * For recvmsg_x(), the size of the data received is given by the field
 * msg_datalen.
 *
 * For sendmsg_x(), the size of the data to send is given by the length of 
 * the iovec array -- like sendmsg(). The field msg_datalen is ignored.
 */
struct msghdr_x {
	void		*msg_name;	/* optional address */
	socklen_t	msg_namelen;	/* size of address */
	struct iovec 	*msg_iov;	/* scatter/gather array */
	int		msg_iovlen;	/* # elements in msg_iov */
	void		*msg_control;	/* ancillary data, see below */
	socklen_t	msg_controllen;	/* ancillary data buffer len */
	int		msg_flags;	/* flags on received message */
	size_t		msg_datalen;	/* byte length of buffer in msg_iov */
};

/*
 * recvmsg_x() is a system call similar to recvmsg(2) to receive
 * several datagrams at once in the array of message headers "msgp".
 *
 * recvmsg_x() can be used only with protocols handlers that have been specially
 * modified to support sending and receiving several datagrams at once.
 * 
 * The size of the array "msgp" is given by the argument "cnt".
 *
 * The "flags" arguments supports only the value MSG_DONTWAIT.
 * 
 * Each member of "msgp" array is of type "struct msghdr_x".
 *
 * The "msg_iov" and "msg_iovlen" are input parameters that describe where to
 * store a datagram in a scatter gather locations of buffers -- see recvmsg(2).
 * On output the field "msg_datalen" gives the length of the received datagram.
 *
 * The field "msg_flags" must be set to zero on input. On output, "msg_flags"
 * may have MSG_TRUNC set to indicate the trailing portion of the datagram was
 * discarded because the datagram was larger than the buffer supplied.
 * recvmsg_x() returns as soon as a datagram is truncated.
 *
 * recvmsg_x() may return with less than "cnt" datagrams received based on
 * the low water mark and the amount of data pending in the socket buffer.
 *
 * recvmsg_x() returns the number of datagrams that have been received,
 * or -1 if an error occurred. 
 *
 * NOTE: This a private system call, the API is subject to change.
 */
ssize_t recvmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);

/*
 * sendmsg_x() is a system call similar to send(2) to send
 * several datagrams at once in the array of message headers "msgp".
 *
 * sendmsg_x() can be used only with protocols handlers that have been specially
 * modified to support sending and receiving several datagrams at once.
 * 
 * The size of the array "msgp" is given by the argument "cnt".
 *
 * The "flags" arguments supports only the value MSG_DONTWAIT.
 * 
 * Each member of "msgp" array is of type "struct msghdr_x".
 *
 * The "msg_iov" and "msg_iovlen" are input parameters that specify the
 * data to be sent in a scatter gather locations of buffers -- see sendmsg(2).
 *
 * sendmsg_x() fails with EMSGSIZE if the sum of the length of the datagrams
 * is greater than the high water mark.
 *
 * Address and ancillary data are not supported so the following fields
 * must be set to zero on input:
 *   "msg_name", "msg_namelen", "msg_control" and "msg_controllen".
 *
 * The field "msg_flags" and "msg_datalen" must be set to zero on input. 
 *
 * sendmsg_x() returns the number of datagrams that have been sent,
 * or -1 if an error occurred. 
 *
 * NOTE: This a private system call, the API is subject to change.
 */
ssize_t sendmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);

#endif