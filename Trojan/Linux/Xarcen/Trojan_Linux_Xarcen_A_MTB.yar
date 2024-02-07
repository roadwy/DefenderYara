
rule Trojan_Linux_Xarcen_A_MTB{
	meta:
		description = "Trojan:Linux/Xarcen.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 42 32 46 41 33 36 41 41 41 39 35 34 31 46 30 } //01 00  BB2FA36AAA9541F0
		$a_00_1 = {44 65 6c 53 65 72 76 69 63 65 5f 66 6f 72 6d 5f 70 69 64 } //01 00  DelService_form_pid
		$a_00_2 = {68 74 74 70 5f 64 6f 77 6e 6c 6f 61 64 } //01 00  http_download
		$a_00_3 = {6b 69 6c 6c 5f 70 69 64 } //01 00  kill_pid
		$a_00_4 = {2f 65 74 63 2f 72 63 2e 64 2f 72 63 25 64 2e 64 2f 53 39 30 25 73 } //01 00  /etc/rc.d/rc%d.d/S90%s
		$a_00_5 = {8b 45 f4 0f b6 08 8b 55 f8 89 d0 c1 fa 1f f7 7d fc 89 d0 0f b6 80 88 f4 0c 08 89 ca 31 c2 8b 45 f4 88 10 83 45 f8 01 83 45 f4 01 8b 45 f8 3b 45 0c 7c cd 8b 45 08 c9 c3 } //01 00 
		$a_00_6 = {2f 65 74 63 2f 63 72 6f 6e 74 61 62 20 26 26 20 65 63 68 6f 20 27 2a 2f 33 20 2a 20 2a 20 2a 20 2a 20 72 6f 6f 74 20 2f 65 74 63 2f 63 72 6f 6e 2e 68 6f 75 72 6c 79 2f 67 63 63 2e 73 68 27 20 3e 3e 20 2f 65 74 63 2f 63 72 6f 6e 74 61 62 } //00 00  /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab
	condition:
		any of ($a_*)
 
}