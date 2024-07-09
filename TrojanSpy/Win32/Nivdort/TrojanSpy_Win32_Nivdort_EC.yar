
rule TrojanSpy_Win32_Nivdort_EC{
	meta:
		description = "TrojanSpy:Win32/Nivdort.EC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 8b 4c 24 [0-0a] 0f b6 31 31 c6 89 f0 88 c2 88 11 } //2
		$a_01_1 = {89 e1 c7 01 e5 08 00 00 ff d0 83 ec 04 } //1
		$a_01_2 = {89 e1 c7 01 f4 01 00 00 ff d0 83 ec 04 } //1
		$a_03_3 = {89 e2 c7 02 c3 62 01 00 89 44 24 ?? ff d1 83 ec 04 } //1
		$a_01_4 = {89 e1 c7 01 1f 04 00 00 ff d0 83 ec 04 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}