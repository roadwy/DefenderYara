
rule TrojanDownloader_Win32_Banload_ZB{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 54 3a ff 8b 4d fc 8a 4c 31 ff 32 d1 e8 } //1
		$a_01_1 = {6a 01 8d 45 f8 50 b1 01 33 d2 b8 06 00 00 00 e8 } //1
		$a_01_2 = {8b f0 46 8d 45 f0 8b 55 f8 8a 54 32 ff e8 d9 75 f9 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}