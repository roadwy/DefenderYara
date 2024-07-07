
rule Trojan_Win32_Dridex_GKM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 14 18 88 13 8d 14 b1 03 d6 4f 8d 54 3a 90 01 01 66 89 15 90 01 04 0f b7 d2 8d 14 92 c1 e2 04 2b d1 43 03 f2 85 ff 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 14 28 88 55 00 8b 15 90 01 04 2b 15 90 01 04 8b ce 2b 0d 90 01 04 4b 83 e9 02 4f 45 89 5c 24 90 01 01 89 0d 90 01 04 81 fa 3e 02 00 00 74 90 01 01 8a 15 90 01 04 2a 15 90 01 04 02 d1 88 15 90 01 04 8b cf 2b ce 81 e9 88 e1 00 00 8b f1 85 db 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {2a d1 80 ea 4e 02 da 8b 15 90 01 04 8b 8c 02 90 01 04 81 c1 04 70 01 01 89 8c 02 90 01 04 83 c0 04 89 0d 90 01 04 8d 74 3e 90 01 01 0f b7 cd 3d 02 12 00 00 72 90 00 } //1
		$a_02_1 = {2b d5 8d b4 3a 90 01 04 8b 15 90 01 04 8b 84 0a 90 01 04 05 9c 11 0e 01 89 84 0a 90 01 04 83 c1 04 a3 90 01 04 81 f9 f0 0e 00 00 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 1e 23 00 00 e8 90 01 04 83 c4 04 a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 8d 84 0a 90 01 04 2b 45 90 01 01 03 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 81 e9 1e 23 00 00 89 0d 90 01 04 8b 15 90 01 04 03 55 90 01 01 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 03 45 90 01 01 8b 0d 90 01 04 2b c8 89 0d 90 01 04 ba 73 00 00 00 85 d2 0f 85 90 01 04 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}