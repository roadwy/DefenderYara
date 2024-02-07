
rule Trojan_BAT_Barys_AMAC_MTB{
	meta:
		description = "Trojan:BAT/Barys.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 20 00 01 00 00 6f 90 01 01 00 00 0a 06 72 90 01 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 72 90 01 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 06 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 73 90 01 01 00 00 0a 0c 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}