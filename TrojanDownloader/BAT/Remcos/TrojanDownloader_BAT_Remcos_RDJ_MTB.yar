
rule TrojanDownloader_BAT_Remcos_RDJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Remcos.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 72 01 00 00 70 28 02 00 00 0a 72 33 00 00 70 28 02 00 00 0a 6f 03 00 00 0a 0c 14 0d } //00 00 
	condition:
		any of ($a_*)
 
}