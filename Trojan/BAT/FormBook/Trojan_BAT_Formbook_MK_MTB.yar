
rule Trojan_BAT_Formbook_MK_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 02 07 91 6f 90 01 03 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8 90 00 } //1
		$a_03_1 = {13 05 16 13 06 00 09 11 05 16 11 05 8e 69 6f 90 01 03 0a 13 06 07 11 05 16 11 06 6f 90 01 03 0a 00 00 11 06 16 fe 02 13 09 11 09 2d d8 90 00 } //1
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}