
rule TrojanDownloader_BAT_Auslogics_SK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Auslogics.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 12 00 00 06 10 00 02 0a dd 03 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}