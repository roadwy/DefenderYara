
rule Trojan_BAT_SnakeKeyLogger_RDBN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 26 00 00 0a 0b 73 27 00 00 0a 0c 08 07 17 73 28 00 00 0a 0d 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}