
rule Trojan_BAT_SnakeKeyLogger_LTI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.LTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 06 00 00 1b 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 11 07 17 58 13 07 11 07 06 75 06 00 00 1b 8e 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}