
rule Trojan_BAT_DarkTortilla_MUAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 13 04 73 90 01 02 00 0a 13 05 11 05 74 90 01 01 00 00 01 11 04 75 90 01 01 00 00 01 17 73 90 01 02 00 0a 13 07 11 07 75 90 01 01 00 00 01 02 16 02 8e 69 6f 90 01 02 00 0a 11 07 90 01 02 00 00 01 6f 90 01 02 00 0a de 16 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}