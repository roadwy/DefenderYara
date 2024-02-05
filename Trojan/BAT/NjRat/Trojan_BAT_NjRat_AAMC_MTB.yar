
rule Trojan_BAT_NjRat_AAMC_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AAMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 08 8e b7 17 da 17 d6 8d 90 01 01 00 00 01 0b 16 13 05 00 11 0a 11 0c 11 06 6f 90 01 01 00 00 0a 13 0d 00 00 11 08 73 90 01 01 00 00 0a 13 0e 00 00 11 0e 11 0d 16 73 90 01 01 00 00 0a 13 0f 00 11 0f 07 16 07 8e b7 6f 90 01 01 00 00 0a 13 05 11 0e 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}