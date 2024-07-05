
rule Trojan_BAT_PureLog_RDF_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0d 09 28 c2 00 00 0a 72 61 01 00 70 6f c3 00 00 0a 6f c4 00 00 0a 13 04 } //00 00 
	condition:
		any of ($a_*)
 
}