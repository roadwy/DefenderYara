
rule TrojanDownloader_Win32_Renos_FW{
	meta:
		description = "TrojanDownloader:Win32/Renos.FW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 02 56 6a fc 0f 95 c1 57 88 0d ?? ?? ?? ?? ff 15 } //1
		$a_01_1 = {35 23 01 ef cd 50 ff 15 } //1
		$a_03_2 = {85 c0 74 19 8b 45 fc c7 05 ?? ?? ?? ?? 00 00 0e d7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}