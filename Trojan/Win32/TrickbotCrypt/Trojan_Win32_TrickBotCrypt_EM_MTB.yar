
rule Trojan_Win32_TrickBotCrypt_EM_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 29 33 d2 8a 14 0e 03 c2 33 d2 f7 35 90 01 04 2b 15 90 01 04 8a 04 0a 8a 17 32 d0 8b 44 24 20 43 88 17 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBotCrypt_EM_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 1c 2b c3 8a 1d 90 01 04 83 c0 02 0f af 05 90 01 04 03 c5 03 c2 8b 54 24 90 01 01 8a 14 0a 02 d3 8a 18 32 da 45 88 18 90 00 } //1
		$a_81_1 = {57 41 3e 68 54 3e 34 45 68 2b 67 4f 5a 51 57 4c 28 6a 25 42 70 31 49 31 3f 6c 2b 6f 25 5a 40 23 54 5a 72 69 69 79 6b 2a 72 35 73 32 72 68 48 76 73 33 52 4a 73 75 72 31 79 66 51 64 6a 69 3e 33 78 34 6f 35 45 29 59 55 34 36 31 59 28 77 5a 23 25 70 45 24 79 4d 4f 59 56 66 2b 47 3e 41 78 41 72 65 6b 65 56 58 69 45 76 34 76 4c 79 41 64 30 } //1 WA>hT>4Eh+gOZQWL(j%Bp1I1?l+o%Z@#TZriiyk*r5s2rhHvs3RJsur1yfQdji>3x4o5E)YU461Y(wZ#%pE$yMOYVf+G>AxArekeVXiEv4vLyAd0
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}