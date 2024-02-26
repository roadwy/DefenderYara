
rule Trojan_BAT_Remcos_ABLS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {11 01 11 06 11 00 11 06 9a 1f 10 7e 90 01 03 04 28 90 01 03 06 9c 20 90 00 } //01 00 
		$a_01_1 = {6f 00 64 00 31 00 43 00 4a 00 58 00 72 00 73 00 6b 00 76 00 58 00 78 00 52 00 6e 00 54 00 66 00 58 00 37 00 2e 00 79 00 72 00 73 00 66 00 5a 00 74 00 32 00 75 00 44 00 53 00 46 00 38 00 46 00 4b 00 4f 00 55 00 32 00 66 } //00 00 
	condition:
		any of ($a_*)
 
}