#!/bin/sh
socat tcp-listen:749,reuseaddr,fork exec:"./passwd_mngr"

