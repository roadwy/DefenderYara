
rule TrojanDownloader_Win32_Senphiv_A{
	meta:
		description = "TrojanDownloader:Win32/Senphiv.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 00 3f 00 90 01 01 6a 74 68 00 01 00 00 90 01 01 e8 90 01 02 ff ff e8 90 01 02 ff ff 68 90 01 04 eb 09 90 00 } //1
		$a_03_1 = {66 b9 59 00 e8 90 01 04 8b 4d 90 01 01 88 01 66 b9 58 00 90 00 } //1
		$a_01_2 = {00 6d 43 68 61 6e 67 65 49 45 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}