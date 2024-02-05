
rule Trojan_BAT_Tedy_NBA_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f 26 00 00 0a 6f 90 01 01 00 00 0a 0a 28 90 01 01 00 00 0a 04 28 90 01 01 00 00 06 16 1f 10 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 02 06 07 28 90 01 01 00 00 06 90 00 } //01 00 
		$a_01_1 = {43 54 6f 6f 6c 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}