
rule TrojanDownloader_BAT_Mallox_IP_MTB{
	meta:
		description = "TrojanDownloader:BAT/Mallox.IP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 03 00 00 06 28 09 00 00 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}