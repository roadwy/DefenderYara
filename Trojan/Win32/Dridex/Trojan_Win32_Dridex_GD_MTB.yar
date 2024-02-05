
rule Trojan_Win32_Dridex_GD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 14 01 8b 75 90 01 01 88 14 06 83 c0 90 01 01 89 45 90 01 01 8b 7d 90 01 01 39 f8 90 13 90 02 20 8b 45 90 01 01 8b 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GD_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {88 e8 f6 e2 88 44 24 90 01 01 8a 44 24 90 01 01 8b 74 24 90 01 01 81 e6 74 db 20 7e 89 74 24 90 01 01 c7 44 24 90 01 01 00 00 00 00 8b 75 90 01 01 8b 7d 90 01 01 88 04 37 8d 65 90 00 } //02 00 
		$a_80_1 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //FFPGGLBM.pdb  02 00 
		$a_80_2 = {42 65 74 61 74 72 65 65 6b 69 6e 67 33 73 65 65 63 65 73 65 73 6f 65 76 69 6e 67 2e 31 32 33 66 6f 72 58 65 6d 65 74 69 66 } //Betatreeking3seecesesoeving.123forXemetif  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GD_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_2 = {72 6f 74 65 63 74 20 62 65 67 69 6e } //01 00 
		$a_01_3 = {2f 2f 46 69 6c 65 41 70 69 2e 67 79 61 6f 2e 74 6f 70 2f 30 30 32 2f 70 75 70 70 } //01 00 
		$a_01_4 = {48 54 54 50 2f 31 2e 31 } //01 00 
		$a_01_5 = {73 77 73 79 71 62 45 52 4d 51 31 67 73 77 73 79 71 62 45 52 4d 51 31 67 73 77 73 79 71 62 45 52 4d 51 31 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GD_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 d8 29 fb 88 d8 88 44 24 90 01 01 8a 44 24 90 01 01 8b 7d 90 01 01 8b 5d 90 01 01 88 04 1f 90 00 } //01 00 
		$a_80_1 = {76 53 69 6c 76 65 72 72 69 67 68 74 31 38 2c 63 61 70 61 62 69 6c 69 74 69 65 73 70 6f 70 75 6c 61 72 69 74 79 77 69 6e 57 69 6e 64 6f 77 73 54 68 65 69 6c 6f 76 65 79 6f 75 } //vSilverright18,capabilitiespopularitywinWindowsTheiloveyou  0a 00 
		$a_02_2 = {40 cc cc cc eb 90 01 01 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 90 01 01 8b 44 24 90 01 01 ff 80 90 01 04 31 c0 c3 c3 90 00 } //0a 00 
		$a_80_3 = {74 74 74 74 33 32 } //tttt32  00 00 
	condition:
		any of ($a_*)
 
}