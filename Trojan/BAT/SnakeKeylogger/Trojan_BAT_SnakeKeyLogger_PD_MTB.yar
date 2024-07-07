
rule Trojan_BAT_SnakeKeyLogger_PD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 16 5d 13 07 11 06 17 58 13 08 07 11 08 07 8e 69 5d 91 13 09 08 11 07 91 13 0a 07 11 06 91 11 0a 61 13 0b 20 e4 8e fb 0e 13 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}