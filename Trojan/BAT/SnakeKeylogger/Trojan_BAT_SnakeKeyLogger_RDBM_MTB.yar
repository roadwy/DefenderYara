
rule Trojan_BAT_SnakeKeyLogger_RDBM_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 03 17 8d 06 00 00 01 25 16 09 20 b9 87 02 00 d6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}