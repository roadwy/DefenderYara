
rule TrojanDownloader_BAT_RedLineStealer_KR_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 7e 90 01 01 00 00 04 fe 90 01 02 00 91 61 d2 6f 90 00 } //01 00 
		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_2 = {47 65 74 54 79 70 65 73 } //00 00  GetTypes
	condition:
		any of ($a_*)
 
}