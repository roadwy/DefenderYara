
rule Trojan_BAT_Tedy_ATY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 25 16 7e 90 01 01 00 00 04 a2 25 17 7e 90 01 01 00 00 04 a2 0b 06 14 28 90 01 01 00 00 0a 2c 12 06 14 17 8d 90 01 03 01 25 16 07 a2 90 00 } //01 00 
		$a_01_1 = {42 00 6f 00 6e 00 6f 00 73 00 75 00 61 00 } //00 00  Bonosua
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Tedy_ATY_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 6f 90 01 03 0a 06 72 1f 00 00 70 6f 90 01 03 0a 06 17 6f 90 01 03 0a 06 17 6f 90 01 03 0a 06 16 6f 90 01 03 0a 06 17 6f 90 01 03 0a 73 16 00 00 0a 25 06 90 00 } //01 00 
		$a_01_1 = {64 65 66 65 6e 64 65 72 20 69 73 6b 6c } //00 00  defender iskl
	condition:
		any of ($a_*)
 
}