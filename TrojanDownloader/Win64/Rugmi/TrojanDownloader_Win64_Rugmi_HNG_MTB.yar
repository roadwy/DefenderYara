
rule TrojanDownloader_Win64_Rugmi_HNG_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 54 8b 44 24 08 48 8b 4c 24 30 48 03 c8 48 8b c1 8b 4c 24 04 0f b6 04 08 88 44 24 02 } //00 00 
	condition:
		any of ($a_*)
 
}