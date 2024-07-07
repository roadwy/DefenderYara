
rule Trojan_BAT_SnakeKeyLogger_RDS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 55 03 00 04 6f c5 00 00 0a 05 03 02 8e 69 6f c6 00 00 0a 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}