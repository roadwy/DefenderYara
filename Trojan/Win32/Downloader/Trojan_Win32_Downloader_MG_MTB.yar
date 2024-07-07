
rule Trojan_Win32_Downloader_MG_MTB{
	meta:
		description = "Trojan:Win32/Downloader.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 85 90 df ff ff 8a 08 88 8d 8b df ff ff 83 85 90 df ff ff 01 80 bd 8b df ff ff 00 75 e2 8b 95 90 df ff ff 2b 95 8c df ff ff 89 95 84 df ff ff 75 } //1
		$a_03_1 = {8b 45 f0 88 08 8b 4d f0 83 c1 01 89 4d f0 8b 55 f8 0f b6 42 02 0f b6 88 90 01 04 c1 e1 06 8b 55 f8 0f b6 42 03 0f b6 90 01 05 0b ca 8b 45 f0 88 08 8b 4d f0 83 c1 01 89 4d f0 8b 55 f8 83 c2 04 89 55 f8 8b 45 f4 83 e8 04 89 45 f4 e9 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}