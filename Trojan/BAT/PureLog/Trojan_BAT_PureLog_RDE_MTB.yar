
rule Trojan_BAT_PureLog_RDE_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 05 73 03 00 00 0a 0b 11 04 73 0c 00 00 0a 0c 08 11 05 16 73 0d 00 00 0a 0d 09 07 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}