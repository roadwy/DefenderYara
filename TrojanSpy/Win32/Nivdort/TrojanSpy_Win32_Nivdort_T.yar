
rule TrojanSpy_Win32_Nivdort_T{
	meta:
		description = "TrojanSpy:Win32/Nivdort.T,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f be 11 8b 45 ?? 0f be 08 33 ca 8b 55 ?? 88 0a } //1
		$a_03_1 = {6a 34 68 30 ?? 44 00 e8 ?? ?? ?? ?? 83 c4 08 } //1
		$a_03_2 = {6a 44 68 d8 ?? 44 00 e8 ?? ?? ?? ?? 83 c4 08 } //1
		$a_03_3 = {6a 20 68 80 ?? 44 00 e8 ?? ?? ?? ?? 83 c4 08 } //1
		$a_03_4 = {6a 7e 68 c0 ?? 44 00 e8 ?? ?? ?? ?? 83 c4 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}