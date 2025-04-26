
rule TrojanDownloader_Win32_Nivdort_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Nivdort.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {f7 f3 8b 45 ?? 01 d0 0f b6 00 31 f0 } //2
		$a_03_1 = {8b 45 f4 ba ?? ?? ?? ?? f7 f1 8b 45 ?? 01 d0 0f b6 00 31 c3 } //2
		$a_03_2 = {f7 f3 0f b6 44 15 ?? 30 04 0e 83 c1 } //2
		$a_03_3 = {89 c8 31 d2 f7 f6 0f b6 44 15 ?? 30 04 0b 83 c1 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=2
 
}