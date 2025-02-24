
rule Trojan_BAT_SnakeKeyLogger_RDCK_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 6f 67 01 00 0a 06 16 06 8e 69 6f 68 01 00 0a 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}