
rule TrojanDownloader_Win64_CobaltStrike_A_MTB{
	meta:
		description = "TrojanDownloader:Win64/CobaltStrike.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 4c 42 02 66 3b 4c 47 02 75 ?? 48 83 c0 02 48 83 f8 0d 74 ?? 0f b7 0c 42 66 3b 0c 47 74 ?? 48 8d 55 10 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}