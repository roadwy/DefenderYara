
rule Trojan_Win32_Dridex_AK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c6 44 24 33 f4 8b 44 24 1c c6 44 24 33 36 66 8b 4c 24 0e 66 0f af c9 8a 50 01 66 89 4c 24 42 0f b6 c2 66 c7 44 24 42 77 c7 83 f8 25 0f 84 d0 fe ff ff e9 74 fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_AK_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b ca 83 c0 21 03 c8 53 55 56 8b 35 90 01 04 2b d1 69 c1 04 67 01 00 83 c6 21 03 f2 90 00 } //0a 00 
		$a_02_1 = {3b c8 74 15 28 8a 90 01 04 8d 04 4d 04 00 00 00 41 a3 90 01 04 03 c8 4a 83 fa 01 7f da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_AK_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {83 c1 f8 89 74 24 14 03 ca 8d 04 4d 06 00 00 00 89 44 24 18 8b 7c 24 1c 8d 50 46 03 d1 8b f2 } //0a 00 
		$a_02_1 = {8b 07 05 cc 10 06 01 89 07 83 c7 04 89 7c 24 1c 33 ff 2b d3 a3 90 01 04 1b ff 2b 54 24 18 1b 7c 24 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_AK_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.AK!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 44 24 0c 8d 34 3a 03 c6 8b d6 8d 04 45 90 ca ff ff 0f b7 c0 89 44 24 0c 8a 4c 24 0c 2a ca 8b 54 24 10 83 44 24 10 04 80 e9 02 8b 02 05 3c 17 0d 01 89 02 66 8b 54 24 0c } //00 00 
	condition:
		any of ($a_*)
 
}