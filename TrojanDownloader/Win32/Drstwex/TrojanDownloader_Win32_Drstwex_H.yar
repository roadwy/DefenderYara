
rule TrojanDownloader_Win32_Drstwex_H{
	meta:
		description = "TrojanDownloader:Win32/Drstwex.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 77 64 73 66 65 72 32 } //1 rewdsfer2
		$a_03_1 = {58 e2 da e9 90 01 04 59 5e a1 90 01 04 8a 1e 32 d8 88 1e eb dc 90 00 } //1
		$a_03_2 = {83 e0 fd 33 c1 05 bd 04 00 00 a3 90 01 04 c1 c8 10 eb 90 03 01 01 0f 0e 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}