
rule Trojan_BAT_SnakeKeylogger_GPD_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0d 08 5d 13 0e 07 11 0e 91 13 0f 11 06 08 5d 08 58 13 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}