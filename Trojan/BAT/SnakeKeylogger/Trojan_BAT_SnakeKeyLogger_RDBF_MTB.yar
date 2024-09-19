
rule Trojan_BAT_SnakeKeyLogger_RDBF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 6f 23 00 00 0a 0c 03 73 24 00 00 0a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}