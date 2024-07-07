
rule Trojan_Win32_DllInject_MB_MTB{
	meta:
		description = "Trojan:Win32/DllInject.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 66 74 76 67 45 64 72 74 63 66 } //2 TftvgEdrtcf
		$a_01_1 = {49 6e 66 66 62 54 76 66 63 72 66 67 } //2 InffbTvfcrfg
		$a_01_2 = {50 6b 6d 6a 6e 4c 6d 69 6e 75 } //2 PkmjnLminu
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 45 78 } //1 WaitForSingleObjectEx
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}
rule Trojan_Win32_DllInject_MB_MTB_2{
	meta:
		description = "Trojan:Win32/DllInject.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 "
		
	strings :
		$a_01_0 = {71 77 65 72 2e 64 6c 6c 00 4f 6e 65 46 00 54 77 6f 46 00 54 68 72 46 } //10
		$a_01_1 = {4f 6e 65 46 } //3 OneF
		$a_01_2 = {54 77 6f 46 } //3 TwoF
		$a_01_3 = {54 68 72 46 } //3 ThrF
		$a_01_4 = {71 77 65 72 2e 64 6c 6c } //3 qwer.dll
		$a_01_5 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1) >=23
 
}
rule Trojan_Win32_DllInject_MB_MTB_3{
	meta:
		description = "Trojan:Win32/DllInject.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 0a d8 e9 d8 e1 d8 ec d8 df 89 11 eb 10 d8 d3 d8 c3 d8 cf 88 0e d8 d1 d8 ce d8 d9 89 0e eb 6a d8 d9 d8 e6 d8 e3 d8 d4 d8 d5 d8 db 8a 0b d8 e0 } //1
		$a_01_1 = {89 0b d8 dd d8 cb d8 c5 89 10 d8 df d8 cf d8 e7 d8 d3 d8 dc d8 e2 d8 c1 d8 db d8 d9 d8 df 89 0a d8 d7 d8 d2 d8 e1 d8 eb d8 cb d8 d3 d8 ce d8 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}