
rule TrojanDownloader_BAT_Heracles_PRA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.PRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 24 00 00 0a 0a 06 02 03 72 0d 00 00 70 28 25 00 00 0a 6f 26 00 00 0a de 0a 06 2c 06 06 6f 27 00 00 0a dc de 0e 28 28 00 00 0a 02 03 28 04 00 00 06 de 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}