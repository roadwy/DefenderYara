
rule Trojan_BAT_Crysan_ABRH_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ABRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 0e 00 00 06 0a 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0b 07 16 07 8e 69 28 90 01 01 00 00 0a 07 0c dd 90 01 01 00 00 00 26 de d4 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}