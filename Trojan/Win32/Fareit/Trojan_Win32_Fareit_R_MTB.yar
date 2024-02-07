
rule Trojan_Win32_Fareit_R_MTB{
	meta:
		description = "Trojan:Win32/Fareit.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 ff 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 } //01 00 
		$a_03_1 = {83 fb 00 7f 90 02 0d 83 c4 78 90 02 15 ff 90 05 01 02 e0 c0 90 0a 50 00 8b 14 1f 90 02 0f e8 90 02 15 89 14 18 90 02 0f 83 fb 00 7f 90 00 } //01 00 
		$a_01_2 = {39 18 90 90 90 90 74 } //00 00 
		$a_00_3 = {78 87 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_R_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 6e 6d 61 72 63 6f 73 37 } //01 00  Sanmarcos7
		$a_01_1 = {46 6c 65 69 73 68 61 63 6b 65 72 35 } //01 00  Fleishacker5
		$a_01_2 = {4f 76 65 72 70 65 72 73 75 61 64 65 36 } //01 00  Overpersuade6
		$a_01_3 = {48 61 6d 6d 65 72 77 69 73 65 35 } //01 00  Hammerwise5
		$a_01_4 = {4b 00 61 00 64 00 75 00 6b 00 61 00 6c 00 69 00 32 00 } //01 00  Kadukali2
		$a_01_5 = {42 00 65 00 42 00 69 00 52 00 64 00 } //01 00  BeBiRd
		$a_01_6 = {4b 00 49 00 6c 00 61 00 74 00 6f 00 73 00 2e 00 65 00 78 00 65 00 } //00 00  KIlatos.exe
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_R_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 72 00 61 00 54 00 54 00 42 00 2e 00 65 00 78 00 65 00 } //01 00  hraTTB.exe
		$a_01_1 = {70 72 65 70 61 72 73 74 61 62 69 6c 65 } //01 00  preparstabile
		$a_01_2 = {70 72 65 70 61 72 42 4c 55 45 47 4f 57 4e } //01 00  preparBLUEGOWN
		$a_01_3 = {70 72 65 70 61 72 53 4c 41 4e 47 49 45 52 } //01 00  preparSLANGIER
		$a_01_4 = {70 72 65 70 61 72 56 4f 4c 4f 53 } //01 00  preparVOLOS
		$a_01_5 = {70 72 65 70 61 72 75 62 69 71 75 69 74 39 } //01 00  preparubiquit9
		$a_01_6 = {70 72 65 70 61 72 54 75 72 75 74 61 70 34 } //00 00  preparTurutap4
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_R_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.R!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 8b f0 8b ca 85 c9 72 10 41 33 d2 8d 3c 32 8a 07 34 e5 88 07 42 49 75 f3 5f 5e } //00 00 
	condition:
		any of ($a_*)
 
}