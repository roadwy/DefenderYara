
rule Trojan_BAT_Remcos_FJN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 e8 03 00 00 73 29 00 00 0a 13 05 09 11 05 09 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 09 11 05 09 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 09 17 6f 90 01 03 0a 00 08 09 6f 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_2 = {6c 00 65 00 65 00 65 00 73 00 } //01 00  leees
		$a_01_3 = {41 00 53 00 44 00 41 00 53 00 66 00 73 00 61 00 66 00 61 00 73 00 66 00 73 00 61 00 66 00 61 00 73 00 66 00 73 00 61 00 66 00 73 00 61 00 66 00 61 00 73 00 66 00 61 00 73 00 } //00 00  ASDASfsafasfsafasfsafsafasfas
	condition:
		any of ($a_*)
 
}