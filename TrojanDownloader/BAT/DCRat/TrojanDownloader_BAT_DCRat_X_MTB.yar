
rule TrojanDownloader_BAT_DCRat_X_MTB{
	meta:
		description = "TrojanDownloader:BAT/DCRat.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 19 9a 74 ?? 00 00 02 07 1b 9a 28 ?? 00 00 0a 07 18 9a 28 ?? ?? 00 0a 07 1c 9a 14 72 ?? ?? 00 70 18 8d ?? 00 00 01 25 16 72 ?? ?? 00 70 a2 25 17 7e ?? ?? 00 0a a2 14 14 14 28 ?? 00 00 0a 14 72 ?? ?? 00 70 18 8d ?? 00 00 01 25 16 72 ?? ?? 00 70 a2 25 17 7e ?? ?? 00 0a a2 14 14 14 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}