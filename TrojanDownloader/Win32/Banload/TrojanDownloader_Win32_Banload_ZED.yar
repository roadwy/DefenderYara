
rule TrojanDownloader_Win32_Banload_ZED{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZED,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 05 83 fb 03 7e de 90 09 1b 00 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 ?? 8b 55 ?? e8 ?? ?? ff ff 43 84 c0 } //1
		$a_03_1 = {7e 2f bf 01 00 00 00 8b c3 34 01 84 c0 74 1b 8d 45 f0 8b 55 fc 0f b6 54 3a ff e8 ?? ?? fe ff 8b 55 f0 8d 45 f8 e8 ?? ?? fe ff 80 f3 01 47 4e 75 d6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}