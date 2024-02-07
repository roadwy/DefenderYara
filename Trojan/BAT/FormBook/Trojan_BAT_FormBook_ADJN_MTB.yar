
rule Trojan_BAT_FormBook_ADJN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ADJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 d2 06 28 90 01 03 06 00 00 09 1b 59 90 00 } //01 00 
		$a_01_1 = {43 00 44 00 6f 00 77 00 6e 00 } //01 00  CDown
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {5a 00 61 00 62 00 61 00 77 00 6b 00 69 00 } //00 00  Zabawki
	condition:
		any of ($a_*)
 
}