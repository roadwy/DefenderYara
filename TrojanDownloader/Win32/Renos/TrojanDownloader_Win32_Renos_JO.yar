
rule TrojanDownloader_Win32_Renos_JO{
	meta:
		description = "TrojanDownloader:Win32/Renos.JO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 44 7e 01 eb [0-20] 8d 34 b5 04 00 00 00 6a 4c 56 } //1
		$a_03_1 = {f7 75 0c 8b 45 08 [0-20] 8a 04 02 02 06 00 45 fe [0-20] 8a 0e 0f b6 45 fe } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}