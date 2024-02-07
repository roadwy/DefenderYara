
rule Trojan_BAT_MarsStealer_AAQM_MTB{
	meta:
		description = "Trojan:BAT/MarsStealer.AAQM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {04 06 18 28 90 01 01 01 00 06 7e 90 01 01 01 00 04 06 1b 28 90 01 01 01 00 06 7e 90 01 01 01 00 04 06 28 90 01 01 01 00 06 0d 7e 90 01 01 01 00 04 09 03 16 03 8e 69 28 90 01 01 01 00 06 2a 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}