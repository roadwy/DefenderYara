
rule Trojan_BAT_FormBook_ABDO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {13 05 18 2c f6 18 2c 2b 07 08 6f 90 01 03 0a 17 73 90 01 03 0a 13 06 11 06 11 05 16 11 05 8e 69 6f 90 01 03 0a de 0c 11 06 2c 07 11 06 6f 90 01 03 0a dc 07 6f 90 01 03 0a 13 07 16 2d bd 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}