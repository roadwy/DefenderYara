
rule TrojanDownloader_Win32_Halnine_B{
	meta:
		description = "TrojanDownloader:Win32/Halnine.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 14 06 d0 fa 80 e2 7f 41 88 10 8b 54 24 10 40 3b ca 72 ec } //1
		$a_01_1 = {8b 44 24 18 c7 44 24 14 00 00 00 00 85 c0 75 21 81 fd 00 00 02 00 b8 00 00 02 00 7f 02 } //1
		$a_01_2 = {73 0e 6a 32 ff 15 28 50 40 00 ff 44 24 10 eb a7 85 c0 c7 44 24 14 00 00 00 00 0f 84 b4 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}