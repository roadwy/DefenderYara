
rule Backdoor_Linux_Gafgyt_ch_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.ch!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {64 65 73 74 5f 68 6f 73 74 3d 60 62 75 73 79 62 6f 78 2b 77 67 65 74 2b 90 01 04 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 2f 62 69 6e 2b 2d 4f 2b 2f 74 6d 70 2f 67 61 66 3b 73 68 2b 2f 74 6d 70 2f 67 61 66 90 00 } //01 00 
		$a_00_1 = {74 63 70 5f 69 70 3d 2d 68 2b 25 36 30 63 64 2b 25 32 46 74 6d 70 25 33 42 2b 72 6d 2b 2d 72 66 2b 41 6d 61 6b 61 6e 6f 2e 6d 70 73 6c 25 33 42 2b 77 67 65 74 2b 68 74 74 70 } //01 00  tcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+Amakano.mpsl%3B+wget+http
		$a_00_2 = {41 6d 61 6b 61 6e 6f 2e 6d 70 73 6c 25 33 42 2b 63 68 6d 6f 64 2b 37 37 37 2b 41 6d 61 6b 61 6e 6f 2e 6d 70 73 6c 25 33 42 2b 2e 25 32 46 41 6d 61 6b 61 6e 6f 2e 6d 70 73 6c 2b 6c 69 6e 6b 73 79 73 25 36 30 26 61 63 74 69 6f 6e 3d 26 74 74 63 70 } //00 00  Amakano.mpsl%3B+chmod+777+Amakano.mpsl%3B+.%2FAmakano.mpsl+linksys%60&action=&ttcp
	condition:
		any of ($a_*)
 
}