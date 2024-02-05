
rule Trojan_BAT_Snakekeylogger_PFH_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.PFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe 0c 06 00 fe 0c 0f 00 fe 0c 06 00 fe 0c 0f 00 91 fe 0c 0f 00 61 d2 9c 00 fe 0c 0f 00 20 01 00 00 00 58 fe 0e 0f 00 fe 0c 0f 00 fe 0c 06 00 8e 69 fe 04 fe 0e 10 00 fe 0c 10 00 3a bf ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}