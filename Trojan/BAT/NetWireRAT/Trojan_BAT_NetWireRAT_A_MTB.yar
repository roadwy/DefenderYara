
rule Trojan_BAT_NetWireRAT_A_MTB{
	meta:
		description = "Trojan:BAT/NetWireRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 57 03 1e 09 07 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 6d 00 00 00 89 00 00 00 dc 00 00 00 d9 01 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {41 70 70 44 6f 6d 61 69 6e } //00 00  AppDomain
	condition:
		any of ($a_*)
 
}