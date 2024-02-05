
rule TrojanDownloader_Win64_CobaltStrike_PE_MTB{
	meta:
		description = "TrojanDownloader:Win64/CobaltStrike.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 c9 48 03 c1 8b 0d 90 01 04 0f af 0d 90 01 04 48 63 c9 48 03 c1 48 63 0d 90 01 04 48 03 c1 48 63 0d 90 01 04 48 2b c1 48 63 0d 90 01 04 48 03 4c 24 90 01 01 0f b6 04 01 8b 4c 24 04 33 c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}