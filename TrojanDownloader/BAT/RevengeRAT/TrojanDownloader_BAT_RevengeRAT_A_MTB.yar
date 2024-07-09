
rule TrojanDownloader_BAT_RevengeRAT_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/RevengeRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 17 9a 75 ?? 00 00 01 20 ?? ?? ?? 1a 28 ?? ?? 00 06 20 00 01 00 00 14 14 14 6f ?? ?? 00 0a a2 20 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}