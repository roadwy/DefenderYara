
rule Trojan_BAT_PureLog_RDA_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 28 11 00 00 0a 28 12 00 00 0a 11 04 6f 13 00 00 0a 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}