
rule TrojanDownloader_Win32_Small_SK_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 ec 8b 55 10 8b 45 f8 89 02 8b 4d f8 c1 e9 09 8b 45 f8 33 d2 be 00 02 00 00 f7 f6 f7 da 1b d2 f7 da 03 ca c1 e1 09 89 4d f4 8b 55 f4 } //00 00 
	condition:
		any of ($a_*)
 
}