
rule Trojan_BAT_FormBook_ESR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ESR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 05 04 5d 91 0a 06 03 05 1f 16 5d 90 01 05 61 0b 2b 00 90 00 } //01 00 
		$a_01_1 = {5a 00 55 00 30 00 35 00 37 00 52 00 48 00 48 00 48 00 39 00 43 00 30 00 47 00 46 00 45 00 59 00 37 00 35 00 54 00 45 00 34 00 34 00 } //01 00  ZU057RHHH9C0GFEY75TE44
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}