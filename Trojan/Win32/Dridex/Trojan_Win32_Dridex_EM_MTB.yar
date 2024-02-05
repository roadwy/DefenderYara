
rule Trojan_Win32_Dridex_EM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {47 65 74 49 66 54 61 62 6c 65 } //GetIfTable  03 00 
		$a_80_1 = {52 65 67 4f 76 65 72 72 69 64 65 50 72 65 64 65 66 4b 65 79 } //RegOverridePredefKey  03 00 
		$a_80_2 = {6c 64 6f 6c 6c 69 72 65 66 67 74 } //ldollirefgt  03 00 
		$a_80_3 = {67 70 6f 69 72 65 65 } //gpoiree  03 00 
		$a_80_4 = {44 44 70 6c 73 6f 65 63 72 56 77 71 61 73 65 } //DDplsoecrVwqase  03 00 
		$a_80_5 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  03 00 
		$a_80_6 = {72 70 69 64 65 62 62 66 6c 6c 2e 70 64 62 } //rpidebbfll.pdb  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } //03 00 
		$a_81_1 = {46 46 50 47 47 4c 42 4d 2e 70 64 62 } //03 00 
		$a_81_2 = {49 73 42 61 64 48 75 67 65 52 65 61 64 50 74 72 } //03 00 
		$a_81_3 = {53 63 72 6f 6c 6c 43 6f 6e 73 6f 6c 65 53 63 72 65 65 6e 42 75 66 66 65 72 41 } //03 00 
		$a_81_4 = {51 75 65 72 79 55 73 65 72 73 4f 6e 45 6e 63 72 79 70 74 65 64 46 69 6c 65 } //03 00 
		$a_81_5 = {53 48 45 6e 75 6d 65 72 61 74 65 55 6e 72 65 61 64 4d 61 69 6c 41 63 63 6f 75 6e 74 73 57 } //03 00 
		$a_81_6 = {59 55 4d 41 66 4a 42 65 74 61 30 39 3a 30 30 69 6e 73 74 61 6c 6c 65 72 2e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 08 0f b6 c1 83 f8 6a 89 44 24 1c } //0a 00 
		$a_01_1 = {8a 08 8b 44 24 50 25 0c 69 3a 7d 89 44 24 50 c7 44 24 54 00 00 00 00 0f b6 c1 3d b8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_EM_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 0c 38 8d 7f 01 4e 88 4f ff 8b c2 2b c6 2d 26 2c 00 00 } //0a 00 
		$a_01_1 = {02 c0 8d 8e 79 d3 ff ff 2a c4 02 c3 66 03 d9 8b 0c 2f 02 c0 81 c1 68 9c 02 01 66 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_EM_MTB_5{
	meta:
		description = "Trojan:Win32/Dridex.EM!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 1c 89 4c 24 48 8b 54 24 20 89 54 24 4c 66 8b 74 24 56 66 83 f6 ff 8a 18 66 89 74 24 56 0f b6 c3 8b 7c 24 5c } //0a 00 
		$a_01_1 = {66 8b 4c 24 56 66 8b 54 24 56 2b 44 24 5c 66 09 d1 66 89 4c 24 56 c7 44 24 2c 5d 09 00 00 89 44 24 18 } //00 00 
	condition:
		any of ($a_*)
 
}