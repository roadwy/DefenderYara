
rule Trojan_BAT_Remcos_ABJB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {13 05 08 6f 90 01 03 0a 11 05 16 11 05 8e 69 6f 90 01 03 0a 13 06 de 59 09 2b cc 07 2b cb 6f 90 01 03 0a 2b c6 13 04 2b c4 08 2b c3 11 04 2b c1 6f 90 01 03 0a 2b bc 08 2b bb 09 2c 06 09 6f 90 01 03 0a dc 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_01_2 = {47 65 74 42 79 74 65 73 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}