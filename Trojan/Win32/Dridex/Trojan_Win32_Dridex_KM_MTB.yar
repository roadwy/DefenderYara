
rule Trojan_Win32_Dridex_KM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 05 e2 38 00 00 03 c6 8d 0c 48 0f b6 05 90 01 04 89 0d 90 01 04 3b f0 74 90 01 01 a0 90 01 04 83 c2 02 83 fa 0d 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_KM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 e0 11 00 00 ff 15 90 01 04 03 05 90 01 04 8b 15 90 01 04 8b 0d 90 01 04 8a 0c 31 88 0c 02 8b 15 90 01 04 83 c2 01 89 15 90 01 04 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_KM_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 d1 8b 0d 90 01 04 81 c1 90 01 04 89 15 90 01 04 03 cf 89 4c 24 90 01 01 8b 31 8a 0d 90 01 04 80 e9 6b 02 d9 81 7c 24 90 01 01 08 1b 00 00 88 1d 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_KM_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f be d1 66 89 d6 66 90 01 04 89 c2 83 c2 01 8a 4c 05 90 01 01 8a 6d 90 01 01 80 c5 a2 38 e9 88 4d 90 01 01 89 55 90 01 01 74 90 01 01 eb 90 00 } //1
		$a_02_1 = {8a 1c 08 88 1c 0a 83 c1 01 89 4c 24 90 01 01 8b 44 24 90 01 01 39 c1 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Dridex_KM_MTB_5{
	meta:
		description = "Trojan:Win32/Dridex.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 8c 10 16 02 00 00 2b 0d 90 01 04 03 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 81 ea 16 02 00 00 89 15 90 01 04 a1 90 01 04 03 05 90 01 04 03 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 2b 0d 90 01 04 89 0d 90 01 04 ba 59 01 00 00 85 d2 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_KM_MTB_6{
	meta:
		description = "Trojan:Win32/Dridex.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 1e 23 00 00 e8 90 01 04 83 c4 04 8b 15 90 01 04 89 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 8d 94 01 90 01 04 2b 55 90 01 01 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 2d 1e 23 00 00 a3 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 03 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 55 90 01 01 a1 90 01 04 2b c2 a3 90 01 04 b9 73 00 00 00 85 c9 0f 85 90 01 04 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}