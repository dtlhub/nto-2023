#!/bin/sh
socat tcp-listen:769,reuseaddr,fork exec:"./poprop"

