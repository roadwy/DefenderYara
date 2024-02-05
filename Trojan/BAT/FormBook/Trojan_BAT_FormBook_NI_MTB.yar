
rule Trojan_BAT_FormBook_NI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 1c 00 00 01 0a 06 16 d0 1b 00 00 01 28 0f 00 00 0a a2 06 17 d0 1c 00 00 01 28 0f 00 00 0a a2 06 28 a2 00 00 0a 14 18 8d 14 00 00 01 0b 07 16 02 8c 1b 00 00 01 a2 07 17 03 a2 07 6f a3 00 00 0a 74 1f 00 00 01 2a } //01 00 
		$a_01_1 = {b5 a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 } //01 00 
		$a_01_2 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}