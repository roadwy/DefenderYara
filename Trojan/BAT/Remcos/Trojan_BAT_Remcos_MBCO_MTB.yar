
rule Trojan_BAT_Remcos_MBCO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 07 11 0c d4 07 11 0c d4 91 11 06 11 06 09 95 11 06 11 04 95 58 20 ff 00 00 00 5f 95 61 } //01 00 
		$a_01_1 = {63 30 61 30 64 64 62 32 30 33 64 64 } //00 00  c0a0ddb203dd
	condition:
		any of ($a_*)
 
}