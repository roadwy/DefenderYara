
rule TrojanDownloader_Win64_CobaltStrike_CCGB_MTB{
	meta:
		description = "TrojanDownloader:Win64/CobaltStrike.CCGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 89 85 68 bd 0d 00 48 8b 8d 68 bd 0d 00 48 8d 15 14 2f 00 00 45 31 c0 45 31 c9 c7 44 24 20 00 00 00 80 48 c7 44 24 28 00 00 00 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}