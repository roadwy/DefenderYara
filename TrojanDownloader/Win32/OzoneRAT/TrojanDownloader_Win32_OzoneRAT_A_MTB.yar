
rule TrojanDownloader_Win32_OzoneRAT_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/OzoneRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 43 04 6a 00 6a 01 6a 02 e8 ?? ff ff ff 89 43 10 66 c7 45 ec 02 00 56 e8 ?? fe ff ff 66 89 45 ee 8b 43 04 50 e8 ?? fe ff ff 89 45 f0 33 c0 5a 59 59 64 89 10 eb } //2
		$a_01_1 = {66 2b 1e 8b cb 0f b7 07 66 d3 e0 66 09 45 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}