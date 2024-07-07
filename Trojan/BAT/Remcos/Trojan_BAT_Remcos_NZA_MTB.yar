
rule Trojan_BAT_Remcos_NZA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 16 02 8e 69 6f 90 01 01 00 00 0a 0a 2b 00 06 90 00 } //1
		$a_01_1 = {62 00 cc 06 59 00 46 06 86 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Remcos_NZA_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 07 00 fe 0c 28 00 20 05 00 00 00 9c fe 0c 1e 00 fe 0c 28 00 7e 90 01 03 04 fe 0c 0f 00 fe 0c 03 00 58 4a 97 29 0d 00 00 11 a2 fe 0c 28 00 20 01 00 00 00 58 fe 0e 28 00 fe 0c 0f 00 90 00 } //1
		$a_01_1 = {62 64 39 31 2d 63 38 61 35 62 37 63 38 39 30 36 66 } //1 bd91-c8a5b7c8906f
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}