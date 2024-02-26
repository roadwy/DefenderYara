
rule Trojan_BAT_NjRat_BCAA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.BCAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {01 25 16 16 8c 90 01 01 00 00 01 a2 14 14 28 90 01 01 00 00 0a 11 0b 17 59 17 58 17 59 17 58 17 59 17 58 8d 90 01 01 00 00 01 13 0c 07 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}