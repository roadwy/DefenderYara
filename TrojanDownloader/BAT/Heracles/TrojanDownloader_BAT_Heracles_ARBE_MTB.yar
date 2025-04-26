
rule TrojanDownloader_BAT_Heracles_ARBE_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.ARBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 07 1f 10 5d 91 61 07 20 ff 00 00 00 5d 28 ?? ?? ?? 06 61 28 ?? ?? ?? 06 9d 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 cc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}