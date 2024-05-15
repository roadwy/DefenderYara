
rule Trojan_BAT_Heracles_NH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {08 06 08 06 93 02 7b 90 01 01 01 00 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_NH_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 03 0c 2b f5 2a 06 6f 90 01 02 00 06 28 90 01 02 00 0a 28 90 01 02 00 0a 2a 90 00 } //01 00 
		$a_01_1 = {4e 6a 72 67 61 6f 73 68 78 78 6f 6f 69 6b 73 72 67 78 74 } //00 00  Njrgaoshxxooiksrgxt
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_NH_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 07 00 "
		
	strings :
		$a_01_0 = {2b 1f 09 11 07 9a 08 28 24 00 00 0a 2c 0d 09 11 07 17 58 9a 13 04 16 } //01 00 
		$a_81_1 = {61 73 70 6e 65 74 5f 77 70 2e 65 78 65 } //01 00  aspnet_wp.exe
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //00 00  CreateEncryptor
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_NH_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 0f 04 00 06 06 20 90 01 03 35 60 0a 6f 90 01 03 0a 20 90 01 03 4e 06 44 90 01 03 ff 02 20 90 01 03 3b 06 60 90 01 03 00 00 04 06 20 90 01 03 3f 61 20 90 01 03 4d 06 5f 0a 02 fe 90 01 04 06 06 20 90 01 03 00 62 0a 73 90 01 03 06 20 90 01 03 18 06 60 0a 6f 90 01 03 0a 02 7b 90 01 03 04 06 20 90 01 03 18 61 20 90 01 03 3e 06 5e 0a 02 20 90 01 03 45 06 20 90 01 03 00 5f 62 0a 90 00 } //01 00 
		$a_01_1 = {47 48 4c 2e 65 78 65 } //00 00  GHL.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_NH_MTB_5{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 06 04 11 07 6f 90 01 02 00 0a 11 05 6f 90 01 02 00 0a 13 08 12 08 28 90 01 02 00 0a 72 90 01 02 00 70 28 90 01 02 00 0a 13 06 11 07 17 58 13 07 11 07 04 6f 90 01 02 00 0a fe 04 13 09 11 09 2d c4 90 00 } //05 00 
		$a_03_1 = {28 aa 01 00 0a 0a 06 18 8d 90 01 03 01 25 16 72 90 01 03 70 a2 25 17 72 90 01 03 70 a2 28 90 01 03 06 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 06 6f 90 01 03 0a 0b 90 00 } //01 00 
		$a_01_2 = {76 00 53 00 53 00 31 00 34 00 6c 00 70 00 57 00 4e 00 6b 00 44 00 43 00 59 00 4c 00 33 00 65 00 45 00 46 00 4f 00 47 00 77 00 45 00 3d 00 } //01 00  vSS14lpWNkDCYL3eEFOGwE=
		$a_01_3 = {4c 00 36 00 6a 00 30 00 47 00 4d 00 49 00 78 00 4f 00 36 00 43 00 53 00 58 00 4c 00 48 00 73 00 66 00 30 00 37 00 30 00 62 00 } //00 00  L6j0GMIxO6CSXLHsf070b
	condition:
		any of ($a_*)
 
}