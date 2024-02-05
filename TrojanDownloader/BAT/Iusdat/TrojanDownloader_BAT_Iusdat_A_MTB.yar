
rule TrojanDownloader_BAT_Iusdat_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Iusdat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 da 51 00 70 0a 06 28 90 01 02 00 0a 0b 07 6f 90 01 02 00 0a 0c 08 6f 90 01 02 00 0a 73 90 01 02 00 0a 6f 90 01 01 00 00 0a 26 73 90 01 01 00 00 0a 06 28 90 01 02 00 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}