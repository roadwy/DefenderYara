
rule TrojanDownloader_BAT_Iusdat_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Iusdat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 da 51 00 70 0a 06 28 ?? ?? 00 0a 0b 07 6f ?? ?? 00 0a 0c 08 6f ?? ?? 00 0a 73 ?? ?? 00 0a 6f ?? 00 00 0a 26 73 ?? 00 00 0a 06 28 ?? ?? 00 0a 26 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}