
rule Trojan_BAT_Injuke_NUAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NUAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {16 13 0e 2b 14 00 11 0d 11 0e 06 11 0b 11 0e 58 91 9c 00 11 0e 17 58 13 0e 11 0e 11 0c fe 04 13 0f 11 0f 2d e0 } //01 00 
		$a_01_1 = {43 00 72 00 65 00 61 00 74 00 65 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}