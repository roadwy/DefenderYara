
rule TrojanDownloader_Win32_Renos_JB{
	meta:
		description = "TrojanDownloader:Win32/Renos.JB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 75 0c 8b 45 08 90 02 20 8a 04 02 02 06 00 45 fe 90 02 20 8a 0e 0f b6 45 fe 90 00 } //1
		$a_01_1 = {0f b6 c0 8a 84 05 fc fe ff ff 32 04 19 88 03 } //1
		$a_03_2 = {68 00 14 2d 00 90 09 03 00 6a 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}