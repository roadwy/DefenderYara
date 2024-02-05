
rule TrojanDownloader_BAT_Seraph_SV_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {28 04 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f 90 01 03 0a 08 6f 90 01 03 0a 13 05 dd 27 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}