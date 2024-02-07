
rule Trojan_Linux_Winnti_A_{
	meta:
		description = "Trojan:Linux/Winnti.A!!Winnti.A,SIGNATURE_TYPE_ARHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 89 45 f0 c7 45 ec 08 01 00 00 c7 45 fc 28 00 00 00 eb 31 8b 45 fc 48 63 d0 48 8b 45 f0 48 01 c2 8b 45 fc 48 63 c8 48 8b 45 f0 48 01 c8 0f b6 00 89 c1 8b 45 f8 89 c6 8b 45 fc 01 f0 31 c8 88 02 83 45 fc 01 } //01 00 
		$a_00_1 = {67 65 74 5f 6f 75 72 5f 70 69 64 73 } //01 00  get_our_pids
		$a_00_2 = {6f 75 72 5f 73 6f 63 6b 65 74 73 } //00 00  our_sockets
	condition:
		any of ($a_*)
 
}