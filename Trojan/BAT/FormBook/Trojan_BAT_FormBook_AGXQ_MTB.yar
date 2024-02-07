
rule Trojan_BAT_FormBook_AGXQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 36 00 07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 17 13 04 00 28 90 01 03 06 d2 06 28 90 01 03 06 00 00 00 09 17 58 90 00 } //01 00 
		$a_01_1 = {4d 00 61 00 6c 00 61 00 67 00 61 00 5f 00 67 00 61 00 6d 00 65 00 } //01 00  Malaga_game
		$a_01_2 = {69 00 6e 00 74 00 65 00 6c 00 32 00 32 00 } //01 00  intel22
		$a_01_3 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_4 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}