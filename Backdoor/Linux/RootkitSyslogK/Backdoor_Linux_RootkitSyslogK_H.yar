
rule Backdoor_Linux_RootkitSyslogK_H{
	meta:
		description = "Backdoor:Linux/RootkitSyslogK.H,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 6e 68 69 64 65 5f 6d 6f 64 75 6c 65 29 } //01 00  unhide_module)
		$a_00_1 = {69 73 5f 69 6e 76 69 73 69 62 6c 65 } //01 00  is_invisible
		$a_00_2 = {73 79 73 6c 6f 67 6b 2e 6d 6f 64 2e 63 } //02 00  syslogk.mod.c
		$a_00_3 = {2f 65 74 63 2f 72 63 2d 5a 6f 62 6b 30 6a 70 69 2f 50 67 53 44 39 33 71 6c } //00 00  /etc/rc-Zobk0jpi/PgSD93ql
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}