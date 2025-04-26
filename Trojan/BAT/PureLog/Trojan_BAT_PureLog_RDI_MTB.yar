
rule Trojan_BAT_PureLog_RDI_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 06 6f 5b 00 00 0a 06 6f 5c 00 00 0a 6f 5d 00 00 0a 0b 1b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}