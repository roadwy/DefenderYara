
rule TrojanDownloader_Win32_Renos_EG{
	meta:
		description = "TrojanDownloader:Win32/Renos.EG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {7e 07 be fe 00 00 00 eb 04 85 f6 7e 15 8d 44 24 08 50 e8 90 01 02 ff ff 8b 44 24 0c 83 c4 04 3b c6 7c eb 90 00 } //1
		$a_01_1 = {33 d6 81 f2 39 30 00 00 52 68 } //1
		$a_03_2 = {68 10 27 00 00 90 01 05 6a 0c 90 01 01 68 00 14 2d 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}