
rule TrojanDownloader_Win32_Zlob_ANN{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 fb c1 ef 02 47 81 fd 80 e0 62 00 8b df 75 } //1
		$a_03_1 = {8b 4c 24 10 8a 8c 01 90 01 04 32 4c 24 1c 48 88 88 90 01 04 79 e8 90 00 } //1
		$a_03_2 = {75 18 8d 84 24 90 01 02 00 00 50 ff 74 24 14 ff 54 24 20 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}