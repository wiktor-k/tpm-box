#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2024 Wiktor Kwapisiewicz <wiktor@metacode.biz>
# SPDX-License-Identifier: CC0-1.0

tpm_server &
sleep 5
tpm2_startup -c -T mssim
