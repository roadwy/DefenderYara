
rule TrojanDownloader_Win64_Brucryp_E{
	meta:
		description = "TrojanDownloader:Win64/Brucryp.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 f7 f2 42 0f b6 04 1a 41 2a 00 41 88 00 ff c6 4d 8d 40 01 41 3b f1 72 e3 } //1
		$a_01_1 = {41 f7 f2 42 0f b6 04 1a 41 2a 00 41 88 00 41 ff c6 4d 8d 40 01 45 3b f1 72 e1 } //1
		$a_03_2 = {41 b8 2a 0a 00 00 48 8b c8 e8 90 01 09 41 b8 14 05 00 00 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}