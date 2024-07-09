
rule TrojanDownloader_Win64_Zenpak_CCHU_MTB{
	meta:
		description = "TrojanDownloader:Win64/Zenpak.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 b8 18 01 00 00 45 33 c9 48 8d 15 ?? ?? ?? ?? 48 8b c8 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}