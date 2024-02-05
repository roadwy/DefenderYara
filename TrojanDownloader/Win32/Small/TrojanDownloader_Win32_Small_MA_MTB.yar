
rule TrojanDownloader_Win32_Small_MA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Small.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 bc 6a 0c 2b 45 b8 59 99 f7 f9 3b f8 0f 83 90 01 04 57 8d 4d b4 e8 90 01 04 50 8d 4d e4 e8 90 01 04 68 90 01 04 6a 04 5e 8d 85 34 ff ff ff 56 53 50 8d 4d e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}