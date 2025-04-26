
rule TrojanDownloader_BAT_PoisonIvy_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/PoisonIvy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 9a 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 08 09 11 04 9c 00 09 17 58 0d 09 07 8e 69 fe } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}