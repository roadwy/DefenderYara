
rule Trojan_BAT_SnakeKeyLogger_RDBV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}