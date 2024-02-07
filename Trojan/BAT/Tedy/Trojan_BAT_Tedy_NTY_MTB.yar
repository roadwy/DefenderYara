
rule Trojan_BAT_Tedy_NTY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 07 1e 02 8e 69 59 02 8e 69 28 90 01 01 00 00 0a 07 16 07 8e 69 1a 5b 1a 5a 03 90 00 } //01 00 
		$a_01_1 = {4e 6f 76 61 6c 69 6e 65 20 49 6e 73 74 61 6c 6c 65 72 } //00 00  Novaline Installer
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Tedy_NTY_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.NTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 6f 90 01 03 0a 0a 02 7b 90 01 03 04 06 6f 90 01 03 0a 02 7b 90 01 03 04 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 2c 1e 72 90 01 03 70 28 90 01 03 0a 26 72 90 01 03 70 90 00 } //01 00 
		$a_01_1 = {62 69 67 62 61 6c 6c 73 76 69 72 75 73 } //00 00  bigballsvirus
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Tedy_NTY_MTB_3{
	meta:
		description = "Trojan:BAT/Tedy.NTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {7b 02 00 00 0a 0a 12 00 25 71 90 01 01 00 00 1b 8c 90 01 01 00 00 1b 3a 90 01 01 00 00 00 26 14 38 90 01 01 00 00 00 fe 90 01 04 1b 6f 90 01 01 00 00 0a a2 25 17 02 7b 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {63 72 75 7a 7a 61 32 38 47 76 66 69 78 } //00 00  cruzza28Gvfix
	condition:
		any of ($a_*)
 
}