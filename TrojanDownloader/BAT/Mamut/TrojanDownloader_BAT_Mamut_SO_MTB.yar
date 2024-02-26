
rule TrojanDownloader_BAT_Mamut_SO_MTB{
	meta:
		description = "TrojanDownloader:BAT/Mamut.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 9a 00 00 06 16 9a 75 19 00 00 1b 0d 08 09 16 09 8e 69 6f 90 01 03 0a 07 6f 90 01 03 0a 13 05 de 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}