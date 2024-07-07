
rule TrojanDownloader_Win32_Banload_ZDT{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZDT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 5c 30 ff 33 5d e4 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 } //1
		$a_03_1 = {6a 05 8d 45 90 01 01 e8 90 09 17 00 dd 5d 90 01 01 9b ff 75 90 01 01 ff 75 90 01 01 8d 45 90 01 01 ba 90 01 04 e8 90 01 02 ff ff 90 00 } //1
		$a_01_2 = {4a 41 48 53 00 ff ff ff ff 01 00 00 00 24 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}