
rule TrojanDownloader_Win32_Cutwail_Y{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.Y,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 54 5d 64 ff 35 18 00 00 00 58 5d c3 } //1
		$a_03_1 = {c7 45 e0 b9 79 37 9e (ff 75 e0|58 8b 45 e0) } //1
		$a_01_2 = {68 20 00 cc 00 68 c8 00 00 00 68 96 00 00 00 6a 00 6a 00 ff 35 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}