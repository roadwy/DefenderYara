
rule Trojan_Win32_Dridex_GE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b c3 2b 05 90 01 04 81 c7 2c 3d 05 01 05 90 01 04 80 c2 90 01 01 66 a3 90 01 04 89 3d 90 01 04 89 bc 2e 90 01 04 8b 0d 90 01 04 02 d2 02 d1 02 15 90 01 04 83 c6 04 81 fe 50 27 00 00 88 54 24 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GE_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b d8 8b fe 83 c9 ff 33 c0 83 c4 04 f2 ae f7 d1 2b f9 8b d1 8b f7 8b fb c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 33 f6 85 ed 76 20 } //01 00 
		$a_01_1 = {68 74 74 70 3a 2f 2f 46 69 6c 65 41 70 69 2e 67 79 61 6f 74 74 2e 74 6f 70 2f 30 30 31 2f 70 75 70 70 65 74 2e 54 78 74 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GE_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {29 c3 88 d8 88 45 90 01 01 8b 5d 90 01 01 8b 45 90 01 01 89 45 90 01 01 8a 45 90 01 01 8b 7d 90 01 01 88 04 3b 89 75 90 01 01 89 4d 90 01 01 89 55 90 01 01 83 c4 90 00 } //01 00 
		$a_02_1 = {66 8b 54 24 04 66 81 c2 32 7b 66 89 54 24 90 01 01 8a 5c 24 90 01 01 88 1c 01 8d 65 f4 5f 5e 90 00 } //05 00 
		$a_02_2 = {40 cc cc cc eb 90 01 01 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 90 01 01 8b 44 24 90 01 01 ff 80 90 01 04 31 c0 c3 c3 90 00 } //05 00 
		$a_02_3 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 90 01 01 8b 44 24 90 01 01 ff 80 90 01 04 31 c0 c3 c3 90 0a 23 00 cc cc cc 40 eb 90 00 } //0a 00 
		$a_80_4 = {74 74 74 74 33 32 } //tttt32  00 00 
	condition:
		any of ($a_*)
 
}