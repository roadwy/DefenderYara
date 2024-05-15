
rule TrojanDownloader_Win64_ZeGost_CCHZ_MTB{
	meta:
		description = "TrojanDownloader:Win64/ZeGost.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 01 fe c8 88 01 48 ff c1 48 ff ca 75 } //00 00 
	condition:
		any of ($a_*)
 
}