
rule TrojanDownloader_Win32_Thoper_D{
	meta:
		description = "TrojanDownloader:Win32/Thoper.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {b9 25 f2 00 00 66 89 4d fc 50 } //1
		$a_01_1 = {81 e9 6a 3b 00 00 66 89 4d fc } //1
		$a_03_2 = {57 b8 25 f2 00 00 68 ?? ?? ?? ?? 56 66 89 44 24 1c } //1
		$a_01_3 = {81 c1 36 79 00 00 66 89 4d fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}