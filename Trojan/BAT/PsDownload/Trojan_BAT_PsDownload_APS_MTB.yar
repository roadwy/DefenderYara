
rule Trojan_BAT_PsDownload_APS_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.APS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 00 07 17 6f 90 01 03 0a 00 06 07 6f 90 01 03 0a 00 06 6f 90 01 03 0a 26 00 de 10 06 14 fe 01 0c 08 2d 07 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}