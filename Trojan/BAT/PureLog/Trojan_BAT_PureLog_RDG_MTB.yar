
rule Trojan_BAT_PureLog_RDG_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 06 28 06 00 00 0a 6f 07 00 00 0a 08 07 28 06 00 00 0a 6f 08 00 00 0a 08 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}