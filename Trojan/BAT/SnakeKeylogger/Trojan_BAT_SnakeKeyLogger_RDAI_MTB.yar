
rule Trojan_BAT_SnakeKeyLogger_RDAI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 0b 91 61 13 0d 20 00 01 00 00 13 06 11 0d 07 11 0c 91 59 11 06 58 11 06 5d 13 0e 07 11 05 11 0e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}