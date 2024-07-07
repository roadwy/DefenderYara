
rule Trojan_BAT_SnakeKeyLogger_RDAJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 04 6f 3c 00 00 0a 5d 6f 3d 00 00 0a 61 d2 9c 11 05 17 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}