
rule Trojan_Win32_TravNet_MA_MTB{
	meta:
		description = "Trojan:Win32/TravNet.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e3 73 c6 45 e4 76 c6 45 e5 63 c6 45 e6 68 c6 45 e7 6f c6 45 e8 73 c6 45 e9 74 c6 45 ea 2e c6 45 eb 74 c6 45 ec 78 c6 45 ed 74 c6 45 ee 00 6a 00 6a 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 55 d4 52 ff 55 } //1
		$a_01_1 = {52 75 6e 44 6c 6c 45 6e 74 72 79 } //1 RunDllEntry
		$a_01_2 = {74 69 6f 6e 43 61 74 63 68 65 72 } //1 tionCatcher
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}