
rule Trojan_BAT_PureLog_RDC_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 03 00 00 0a 28 01 00 00 2b 72 01 00 00 70 6f 05 00 00 0a 14 14 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}