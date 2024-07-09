
rule TrojanDownloader_Win64_Snojan_DL_MTB{
	meta:
		description = "TrojanDownloader:Win64/Snojan.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 48 8b 8c 24 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f be 84 04 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 40 48 8b 15 ?? ?? ?? ?? 88 04 0a e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}