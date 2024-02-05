
rule Trojan_BAT_Sakeeya_CNP_MTB{
	meta:
		description = "Trojan:BAT/Sakeeya.CNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 05 02 28 90 01 04 13 04 28 90 01 04 11 05 11 04 16 11 04 8e b7 6f 90 01 04 6f 90 01 04 0a 06 0d 90 00 } //01 00 
		$a_01_1 = {43 00 72 00 37 00 52 00 6f 00 6e 00 61 00 6c 00 64 00 6f 00 } //01 00 
		$a_01_2 = {7a 00 69 00 64 00 65 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}