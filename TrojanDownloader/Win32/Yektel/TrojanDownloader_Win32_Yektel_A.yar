
rule TrojanDownloader_Win32_Yektel_A{
	meta:
		description = "TrojanDownloader:Win32/Yektel.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {47 66 81 ff 28 23 7d 52 33 c0 89 04 24 54 6a 00 55 e8 ?? ?? ff ff e8 ?? ?? ff ff } //1
		$a_03_1 = {66 3d 19 04 74 06 66 3d 22 04 75 ?? a1 ?? ?? ?? ?? 8b 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}