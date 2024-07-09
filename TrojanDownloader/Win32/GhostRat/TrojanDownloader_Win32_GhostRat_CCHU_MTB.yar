
rule TrojanDownloader_Win32_GhostRat_CCHU_MTB{
	meta:
		description = "TrojanDownloader:Win32/GhostRat.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 49 00 8a 8c 15 ?? ?? ?? ?? fe c9 88 8c 15 ?? ?? ?? ?? 42 3b d0 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}