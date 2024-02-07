
rule Trojan_BAT_Nanocore_ABRB_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 04 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 03 06 28 90 01 03 06 74 90 01 03 01 28 90 01 03 06 74 90 01 03 1b 28 90 01 03 06 0a dd 90 01 03 00 26 de d3 06 2a 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //00 00  ReadAsByteArrayAsync
	condition:
		any of ($a_*)
 
}