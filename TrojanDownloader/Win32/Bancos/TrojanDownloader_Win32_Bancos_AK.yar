
rule TrojanDownloader_Win32_Bancos_AK{
	meta:
		description = "TrojanDownloader:Win32/Bancos.AK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 83 eb 02 66 83 fb 03 76 40 8d 45 f0 50 0f b7 d3 b9 03 00 00 00 8b 45 fc e8 ?? ?? ?? ?? 8b 45 f0 e8 ?? ?? ?? ?? 8b f8 66 2b 7d fa 8d 45 ec 8b d7 e8 ?? ?? ?? ?? 8b 55 ec 8b c6 e8 ?? ?? ?? ?? 66 83 eb 03 66 83 fb 03 77 c0 } //1
		$a_03_1 = {ba 0f 00 00 00 e8 ?? ?? fb ff 8b 85 ?? ?? ff ff e8 ?? ?? fb ff 50 6a 00 e8 ?? ?? fb ff 8d 55 f8 b8 ?? ?? 44 00 e8 ?? ?? ff ff 8d 55 f4 b8 ?? ?? 44 00 e8 ?? ?? ff ff 8d 55 f0 } //1
		$a_03_2 = {ba 0f 00 00 00 e8 ?? ?? fb ff 8b 85 ?? ?? ff ff e8 ?? ?? fb ff 50 6a 00 e8 ?? ?? fb ff 8b 45 ec e8 ?? ?? fb ff 84 c0 75 4f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}