
rule TrojanDownloader_Win64_CobaltStrike_RJD_MTB{
	meta:
		description = "TrojanDownloader:Win64/CobaltStrike.RJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 08 8b 45 18 41 89 c0 48 8b 55 e8 48 8b 45 f8 48 01 d0 44 31 c1 89 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}