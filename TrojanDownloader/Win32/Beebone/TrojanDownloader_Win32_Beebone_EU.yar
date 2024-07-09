
rule TrojanDownloader_Win32_Beebone_EU{
	meta:
		description = "TrojanDownloader:Win32/Beebone.EU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 58 59 59 59 ff 90 04 01 01 75 } //2
		$a_03_1 = {ff ff 08 00 00 00 6a 63 e8 ?? ?? ?? ?? 89 85 ?? ?? ff ff c7 85 ?? ?? ff ff 08 00 00 00 6a 6f e8 ?? ?? ?? ff 89 85 ?? ?? ff ff c7 85 ?? ?? ff ff 08 00 00 00 6a 6d e8 ?? ?? ?? ff 89 85 ?? ?? ff ff c7 85 ?? ?? ff ff 08 00 00 00 6a 3a e8 ?? ?? ?? ff 89 85 ?? ?? ff ff c7 85 ?? ?? ff ff 08 00 00 00 6a 34 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}