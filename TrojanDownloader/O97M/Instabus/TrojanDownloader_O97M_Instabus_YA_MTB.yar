
rule TrojanDownloader_O97M_Instabus_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Instabus.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6d 73 69 65 78 65 63 90 02 5a 2f 69 20 68 74 74 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}