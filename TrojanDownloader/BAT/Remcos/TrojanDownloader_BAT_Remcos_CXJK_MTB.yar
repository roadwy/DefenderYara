
rule TrojanDownloader_BAT_Remcos_CXJK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Remcos.CXJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 33 00 37 00 2f } //00 00 
	condition:
		any of ($a_*)
 
}