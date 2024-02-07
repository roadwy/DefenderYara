
rule Trojan_BAT_Androm_ABNC_MTB{
	meta:
		description = "Trojan:BAT/Androm.ABNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 11 01 6f 90 01 03 0a 72 90 01 03 70 7e 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a 1b 3a 90 01 03 00 26 38 90 01 03 00 dd 90 01 03 00 13 01 90 0a 49 00 72 90 01 03 70 28 90 01 03 06 17 3a 90 01 03 00 26 38 90 01 03 00 28 90 00 } //01 00 
		$a_01_1 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {47 65 74 54 79 70 65 73 } //00 00  GetTypes
	condition:
		any of ($a_*)
 
}