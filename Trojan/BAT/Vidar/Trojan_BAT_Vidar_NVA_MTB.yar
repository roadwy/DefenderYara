
rule Trojan_BAT_Vidar_NVA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f 76 00 00 0a 0b 07 02 16 02 8e 69 6f 90 01 01 00 00 0a 0c 08 0d 90 00 } //01 00 
		$a_01_1 = {43 00 6f 00 37 00 66 00 65 00 72 00 65 00 37 00 63 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Vidar_NVA_MTB_2{
	meta:
		description = "Trojan:BAT/Vidar.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 03 11 07 16 73 90 01 01 00 00 0a 13 0b 20 90 01 01 00 00 00 7e 90 01 01 00 00 04 7b 90 01 01 00 00 04 39 90 01 01 00 00 00 26 20 90 01 01 00 00 00 38 90 01 01 00 00 00 fe 0c 09 00 90 00 } //01 00 
		$a_01_1 = {66 69 6e 61 6c 2e 42 72 69 64 67 65 73 2e 49 6e 64 65 78 65 72 52 65 70 6f 73 69 74 6f 72 79 42 72 69 64 67 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_2 = {51 69 72 68 6b 72 79 67 62 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}