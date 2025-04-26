
rule TrojanDownloader_Win32_Unruy_S{
	meta:
		description = "TrojanDownloader:Win32/Unruy.S,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 6a 00 56 68 02 04 00 00 8b 48 04 89 4e 08 8b 00 ff 70 04 a1 ?? ?? ?? ?? ff 90 90 ?? ?? 00 00 } //1
		$a_03_1 = {68 14 00 00 c8 57 66 c7 45 dc 02 00 66 89 75 de 66 c7 45 ec 02 00 66 89 75 ee 89 75 f0 89 75 fc ff 90 90 ?? ?? 00 00 a1 ?? ?? ?? ?? 57 ff 90 90 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}