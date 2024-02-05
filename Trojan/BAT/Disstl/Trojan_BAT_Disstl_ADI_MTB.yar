
rule Trojan_BAT_Disstl_ADI_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {a2 25 17 28 90 01 03 0a a2 25 18 72 50 01 00 70 a2 25 19 02 7b 05 00 00 04 a2 25 1a 72 54 01 00 70 a2 28 90 01 03 0a 0c 07 06 90 00 } //01 00 
		$a_01_1 = {5c 64 65 62 75 67 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 50 63 43 6c 65 61 6e 65 72 5c 50 63 43 6c 65 61 6e 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 50 63 43 6c 65 61 6e 65 72 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Disstl_ADI_MTB_2{
	meta:
		description = "Trojan:BAT/Disstl.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {20 80 00 00 00 6f 57 00 00 0a 00 06 20 00 01 00 00 6f 58 00 00 0a 00 06 17 6f 59 00 00 0a 00 06 18 6f 5a 00 00 0a 00 06 28 5b 00 00 0a 03 6f 5c 00 00 0a 6f 5d 00 00 0a 00 06 28 5b 00 00 0a 04 6f 5c 00 00 0a 6f 5e 00 00 0a 00 06 06 6f 5f 00 00 0a 06 6f 60 00 00 0a 6f 68 00 00 0a 0b 7e 69 00 00 0a 0c 02 28 } //01 00 
		$a_01_1 = {46 00 75 00 63 00 6b 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}