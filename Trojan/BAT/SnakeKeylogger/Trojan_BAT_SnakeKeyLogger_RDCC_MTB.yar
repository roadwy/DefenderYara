
rule Trojan_BAT_SnakeKeyLogger_RDCC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 09 03 09 91 05 09 07 5d 91 61 d2 9c 00 09 17 58 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}