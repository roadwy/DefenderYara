
rule Trojan_BAT_Remcos_AOBD_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AOBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 04 08 11 04 08 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 08 11 04 08 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 08 17 6f 90 01 03 0a 28 90 01 03 06 13 05 07 08 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}