
rule Trojan_Linux_Whirpool_A_MTB{
	meta:
		description = "Trojan:Linux/Whirpool.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {c7 00 20 32 3e 26 66 c7 40 04 31 00 } //01 00 
		$a_01_1 = {53 53 4c 53 68 65 6c 6c 2e 63 } //01 00  SSLShell.c
		$a_01_2 = {70 6c 61 69 6e 5f 63 6f 6e 6e 65 63 74 } //00 00  plain_connect
	condition:
		any of ($a_*)
 
}