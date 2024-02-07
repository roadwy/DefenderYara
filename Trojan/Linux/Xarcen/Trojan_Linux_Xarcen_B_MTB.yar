
rule Trojan_Linux_Xarcen_B_MTB{
	meta:
		description = "Trojan:Linux/Xarcen.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 42 32 46 41 33 36 41 41 41 39 35 34 31 46 30 } //01 00  BB2FA36AAA9541F0
		$a_00_1 = {44 65 6c 53 65 72 76 69 63 65 5f 66 6f 72 6d 5f 70 69 64 } //01 00  DelService_form_pid
		$a_00_2 = {62 79 70 61 73 73 5f 69 70 74 61 62 6c 65 73 } //01 00  bypass_iptables
		$a_00_3 = {48 69 64 65 50 69 64 50 6f 72 74 } //01 00  HidePidPort
		$a_00_4 = {2f 65 74 63 2f 72 63 2e 64 2f 72 63 25 64 2e 64 2f 53 39 30 25 73 } //01 00  /etc/rc.d/rc%d.d/S90%s
		$a_00_5 = {10 30 1b e5 00 40 d3 e5 14 30 1b e5 03 00 a0 e1 18 10 1b e5 45 1a 00 eb 01 30 a0 e1 48 20 9f e5 03 30 d2 e7 03 30 24 e0 73 20 ef e6 10 30 1b e5 00 20 c3 e5 14 30 1b e5 01 30 83 e2 14 30 0b e5 10 30 1b e5 01 30 83 e2 10 30 0b e5 14 20 1b e5 24 30 1b e5 03 00 52 e1 e8 ff ff ba } //01 00 
		$a_00_6 = {2a 2f 33 20 2a 20 2a 20 2a 20 2a 20 72 6f 6f 74 20 2f 65 74 63 2f 63 72 6f 6e 2e 68 6f 75 72 6c 79 2f 63 72 6f 6e 2e 73 68 27 20 3e 3e 20 2f 65 74 63 2f 63 72 6f 6e 74 61 62 } //01 00  */3 * * * * root /etc/cron.hourly/cron.sh' >> /etc/crontab
		$a_00_7 = {31 30 33 2e 32 35 2e 39 2e 32 32 39 } //00 00  103.25.9.229
	condition:
		any of ($a_*)
 
}