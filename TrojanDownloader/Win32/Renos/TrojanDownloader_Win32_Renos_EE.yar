
rule TrojanDownloader_Win32_Renos_EE{
	meta:
		description = "TrojanDownloader:Win32/Renos.EE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b ca 68 14 10 00 00 50 51 53 ff 15 ?? ?? ?? ?? 83 f8 06 75 ?? 8d ?? 20 } //1
		$a_03_1 = {68 98 04 02 00 8b ?? 08 90 09 06 00 6a 1c 8d ?? 9c } //1
		$a_01_2 = {0f 85 31 02 00 00 53 56 57 6a 01 8d 44 24 24 6a 20 50 6a 00 } //1
		$a_01_3 = {77 69 6e 61 6c 65 72 74 00 } //1
		$a_01_4 = {2d fb 02 25 b6 06 ba 25 } //1
		$a_01_5 = {2d de 24 04 80 6c d0 49 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}