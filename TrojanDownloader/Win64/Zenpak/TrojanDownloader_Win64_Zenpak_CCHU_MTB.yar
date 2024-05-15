
rule TrojanDownloader_Win64_Zenpak_CCHU_MTB{
	meta:
		description = "TrojanDownloader:Win64/Zenpak.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 b8 18 01 00 00 45 33 c9 48 8d 15 90 01 04 48 8b c8 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}