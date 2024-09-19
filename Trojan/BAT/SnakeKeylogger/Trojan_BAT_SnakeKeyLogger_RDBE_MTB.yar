
rule Trojan_BAT_SnakeKeyLogger_RDBE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 6f 4c 00 00 0a 03 16 03 8e 69 6f 4d 00 00 0a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}