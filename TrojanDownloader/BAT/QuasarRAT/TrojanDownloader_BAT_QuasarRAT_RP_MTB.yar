
rule TrojanDownloader_BAT_QuasarRAT_RP_MTB{
	meta:
		description = "TrojanDownloader:BAT/QuasarRAT.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 0d 00 00 06 28 02 00 00 06 0a 06 6f 04 00 00 06 2a } //1
		$a_03_1 = {09 11 04 a3 ?? ?? 00 01 13 05 11 05 6f ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 0a 39 ?? ?? 00 00 02 11 05 08 28 ?? ?? 00 06 11 04 17 58 13 04 11 04 09 8e 69 32 ca } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}