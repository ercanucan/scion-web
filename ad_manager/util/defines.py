"""
:mod:`defines` --- Constants
============================
Contains constant definitions used for SCION web.
"""

# Values related to the suggested default values
DEFAULT_BANDWIDTH = 1000
SCION_SUGGESTED_PORT = 31000

# Values related to the SCION coordination service API
COORD_SERVICE_URI = "https://coord.scionproto.net"
UPLOAD_JOIN_REQUEST_SVC = "/api/as/uploadJoinRequest/"
UPLOAD_JOIN_REPLY_SVC = "/api/as/uploadJoinReply/"
POLL_JOIN_REPLY_SVC = "/api/as/pollJoinReply/"
UPLOAD_CONN_REQUEST_SVC = "/api/as/uploadConnRequest/"
UPLOAD_CONN_REPLY_SVC = "/api/as/uploadConnReply/"
POLL_CONN_REPLY_SVC = "/api/as/pollConnReply/"
POLL_EVENTS_SVC = "/api/as/pollEvents/"
