
rule Trojan_BAT_Ader_PSDH_MTB{
	meta:
		description = "Trojan:BAT/Ader.PSDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {00 04 6f 09 00 00 0a 0a 16 0b 2b 19 00 03 07 03 07 91 66 06 07 04 6f 0a 00 00 0a 5d 93 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0c 08 2d dd 03 0d 2b 00 09 2a } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_3 = {45 6e 75 6d 65 72 61 62 6c 65 } //00 00  Enumerable
	condition:
		any of ($a_*)
 
}