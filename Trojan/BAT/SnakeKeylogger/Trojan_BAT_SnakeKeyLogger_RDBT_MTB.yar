
rule Trojan_BAT_SnakeKeyLogger_RDBT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 10 17 58 08 5d 91 13 12 07 11 10 91 11 11 61 11 12 59 20 00 02 00 00 58 13 13 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}