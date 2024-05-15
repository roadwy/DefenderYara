
rule Trojan_BAT_LummaStealer_NL_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f c5 07 00 0a 26 02 28 90 01 01 07 00 0a 0a 90 00 } //02 00 
		$a_03_1 = {28 c7 07 00 0a 06 16 06 8e 69 6f 90 01 01 07 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LummaStealer_NL_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {8d 06 00 00 01 14 14 14 28 44 00 00 0a 28 52 00 00 0a 02 } //03 00 
		$a_03_1 = {7b 66 00 00 04 14 72 90 01 01 01 00 70 16 8d 90 01 01 00 00 01 14 14 14 28 90 01 01 00 00 0a 28 37 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LummaStealer_NL_MTB_3{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {06 28 9e 00 00 0a 39 90 01 01 00 00 00 7e 90 01 01 00 00 04 74 2f 00 00 01 2a 07 17 58 0b 07 7e 3e 00 00 04 8e 69 3f d2 ff ff ff 90 00 } //03 00 
		$a_03_1 = {02 6f 9a 00 00 0a 6f 90 01 01 00 00 0a 25 7e 90 01 01 00 00 04 74 2f 00 00 01 6f 9a 00 00 0a 6f 9b 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LummaStealer_NL_MTB_4{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 13 16 11 16 20 90 01 03 80 2e 1d 11 16 20 90 01 03 7f 2e 14 08 11 05 07 91 11 06 07 91 58 58 0c 08 20 90 01 03 00 5d 0c 11 05 07 91 13 0f 11 05 07 11 05 08 91 9c 11 05 08 11 0f 9c 07 17 58 0b 07 20 00 01 00 00 32 b7 90 00 } //01 00 
		$a_01_1 = {6b 6a 63 62 6b 6a 69 77 } //00 00  kjcbkjiw
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_LummaStealer_NL_MTB_5{
	meta:
		description = "Trojan:BAT/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {1f 10 8d 76 00 00 01 13 14 11 09 28 90 01 03 0a 16 11 14 16 1a 28 90 01 03 0a 11 0a 28 36 90 00 } //01 00 
		$a_01_1 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 6d 00 5f 00 63 00 61 00 74 00 65 00 67 00 6f 00 72 00 69 00 65 00 73 00 5f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 73 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //00 00  programm_categories_products_update.exe
	condition:
		any of ($a_*)
 
}