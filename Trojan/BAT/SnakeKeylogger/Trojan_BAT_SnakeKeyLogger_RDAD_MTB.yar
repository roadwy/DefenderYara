
rule Trojan_BAT_SnakeKeyLogger_RDAD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 bf 00 00 0a 02 6f c0 00 00 0a 6f c1 00 00 0a 1f 23 9a 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}