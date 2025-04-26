
rule Trojan_Win32_Zenpak_MA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 45 f4 89 4d f0 89 55 ec 89 7d e8 89 75 e4 74 2b 8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 e2 } //10
		$a_01_1 = {09 08 00 00 05 00 00 20 14 00 00 02 00 00 24 11 00 00 00 10 } //5
		$a_01_2 = {47 65 74 4f 70 65 6e 46 69 6c 65 4e 61 6d 65 41 } //1 GetOpenFileNameA
		$a_01_3 = {4d 6f 64 75 6c 65 33 32 4e 65 78 74 57 } //1 Module32NextW
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=17
 
}