
rule Trojan_Win32_Dridex_GF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {81 c7 d4 e0 08 01 89 3d 90 01 04 89 bc 2e 90 01 04 8a 15 90 01 04 66 8b 0d 90 01 04 8a c2 02 c1 83 c6 04 2c 90 01 01 81 fe 33 1c 00 00 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GF_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 54 24 0c 05 c8 50 04 01 83 44 24 90 01 01 04 a3 90 01 04 89 02 8b 15 90 01 04 2b 54 24 90 01 01 8b 44 24 90 01 01 81 c2 14 82 01 00 83 6c 24 90 01 01 01 89 15 90 01 04 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GF_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 14 24 89 44 24 90 01 01 c7 44 24 90 01 05 89 74 24 90 01 01 89 4c 24 90 01 01 e8 90 00 } //05 00 
		$a_02_1 = {40 cc cc cc eb 90 01 01 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 90 01 01 8b 44 24 90 01 01 ff 80 90 01 04 31 c0 c3 c3 90 00 } //05 00 
		$a_02_2 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 90 01 01 8b 44 24 90 01 01 ff 80 90 01 04 31 c0 c3 c3 90 0a 23 00 cc cc cc 40 eb 90 00 } //0a 00 
		$a_80_3 = {74 74 74 74 33 32 } //tttt32  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GF_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {66 8b b4 24 90 01 04 66 03 b4 24 90 01 04 66 89 b4 24 90 01 04 c6 44 24 90 01 01 00 c6 44 24 90 01 02 8b 4c 24 90 01 01 89 8c 24 90 01 04 89 44 24 90 01 01 e8 90 01 04 8b 8c 24 90 01 04 89 04 24 89 4c 24 04 e8 90 00 } //0a 00 
		$a_02_1 = {65 c6 84 24 90 01 04 83 c6 84 24 90 01 04 6c c6 84 24 90 01 04 33 c6 84 24 90 01 04 32 c6 84 24 90 01 04 2e 66 8b 94 24 90 01 04 c6 84 24 90 01 04 64 c6 84 24 90 01 04 6c c6 84 24 90 01 04 6c c6 84 24 90 01 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}