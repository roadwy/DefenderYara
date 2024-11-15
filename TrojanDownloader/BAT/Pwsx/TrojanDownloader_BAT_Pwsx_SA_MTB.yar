
rule TrojanDownloader_BAT_Pwsx_SA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Pwsx.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 02 28 75 00 00 0a 13 07 03 11 05 16 61 d2 6f 76 00 00 0a 00 03 11 06 16 61 d2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}