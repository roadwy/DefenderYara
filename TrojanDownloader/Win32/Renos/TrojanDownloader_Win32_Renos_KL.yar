
rule TrojanDownloader_Win32_Renos_KL{
	meta:
		description = "TrojanDownloader:Win32/Renos.KL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c4 56 50 e8 ?? ?? 00 00 8b 35 ?? ?? ?? ?? 59 59 50 ff 75 fc ff d6 89 45 f8 } //1
		$a_03_1 = {81 7d 0c 2c 01 00 00 0f 8c ?? ?? 00 00 81 7d 0c 8f 01 00 00 0f 8f ?? ?? 00 00 } //1
		$a_03_2 = {68 00 14 2d 00 ff 74 24 ?? ff 15 ?? ?? ?? 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}