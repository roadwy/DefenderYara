
rule Trojan_BAT_PureLog_RDH_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 09 07 18 6f 82 00 00 0a 1f 10 28 83 00 00 0a 6f 51 00 00 0a 07 18 58 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}