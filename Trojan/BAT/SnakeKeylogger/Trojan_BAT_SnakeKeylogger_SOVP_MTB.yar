
rule Trojan_BAT_SnakeKeylogger_SOVP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SOVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 07 91 13 08 11 06 08 58 08 5d 13 09 07 11 09 91 11 08 61 13 0a 11 06 17 58 08 58 08 5d 13 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}