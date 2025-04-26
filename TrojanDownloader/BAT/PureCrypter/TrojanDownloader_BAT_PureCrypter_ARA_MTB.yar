
rule TrojanDownloader_BAT_PureCrypter_ARA_MTB{
	meta:
		description = "TrojanDownloader:BAT/PureCrypter.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 11 04 6f ?? ?? ?? 0a 13 06 08 09 25 17 58 0d 12 06 28 ?? ?? ?? 0a 9c 11 05 17 58 13 05 11 05 07 6f ?? ?? ?? 0a 32 d6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}