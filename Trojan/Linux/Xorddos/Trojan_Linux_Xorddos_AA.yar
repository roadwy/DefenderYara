
rule Trojan_Linux_Xorddos_AA{
	meta:
		description = "Trojan:Linux/Xorddos.AA,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 65 74 63 2f 63 72 6f 6e 2e 68 6f 75 72 6c 79 2f 67 63 63 2e 73 68 } //02 00  /etc/cron.hourly/gcc.sh
		$a_00_1 = {2f 65 74 63 2f 63 72 6f 6e 74 61 62 20 26 26 20 65 63 68 6f 20 27 2a 2f 33 20 2a 20 2a 20 2a 20 2a 20 72 6f 6f 74 20 2f 65 74 63 2f 63 72 6f 6e 2e 68 6f 75 72 6c 79 2f 67 63 63 2e 73 68 27 20 3e 3e 20 2f 65 74 63 2f 63 72 6f 6e 74 61 62 } //02 00  /etc/crontab && echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab
		$a_00_2 = {63 70 20 2f 6c 69 62 2f 6c 69 62 75 64 65 76 2e 73 6f 20 2f 6c 69 62 2f 6c 69 62 75 64 65 76 2e 73 6f 2e 36 } //00 00  cp /lib/libudev.so /lib/libudev.so.6
	condition:
		any of ($a_*)
 
}