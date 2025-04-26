
rule TrojanDownloader_BAT_Heracles_SAK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.SAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 12 06 28 1d 00 00 0a 09 08 11 04 18 6f 1e 00 00 0a 1f 10 28 1f 00 00 0a 6f 20 00 00 0a dd 0f 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}