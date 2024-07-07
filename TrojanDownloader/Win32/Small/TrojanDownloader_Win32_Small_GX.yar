
rule TrojanDownloader_Win32_Small_GX{
	meta:
		description = "TrojanDownloader:Win32/Small.GX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 38 5b 01 00 8b 15 90 01 02 40 00 52 ff d6 68 b8 22 00 00 ff 15 90 01 02 40 00 43 89 9d 90 01 02 ff ff eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}