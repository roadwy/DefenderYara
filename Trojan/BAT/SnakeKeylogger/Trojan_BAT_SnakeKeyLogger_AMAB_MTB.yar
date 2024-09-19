
rule Trojan_BAT_SnakeKeyLogger_AMAB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 5d 08 58 13 [0-09] 5d 13 [0-14] 61 [0-05] 59 20 00 02 00 00 58 13 [0-0a] 20 00 01 00 00 5d 13 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}