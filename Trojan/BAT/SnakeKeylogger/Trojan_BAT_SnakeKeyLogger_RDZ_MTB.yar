
rule Trojan_BAT_SnakeKeyLogger_RDZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 2f 00 00 0a 02 6f 30 00 00 0a 0a 06 6f 31 00 00 0a 0b 07 16 9a 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}