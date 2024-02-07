
rule Trojan_BAT_Bladabindi_NTE_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 13 00 00 0a 0a 06 72 90 01 01 00 00 70 6f 90 01 01 00 00 0a 0b 28 90 01 01 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 0c 08 07 28 90 01 01 00 00 0a 00 73 90 01 01 00 00 0a 0d 90 00 } //01 00 
		$a_01_1 = {61 75 66 64 65 6d 77 65 67 7a 75 72 68 61 6c 74 65 73 74 65 6c 6c 65 } //00 00  aufdemwegzurhaltestelle
	condition:
		any of ($a_*)
 
}