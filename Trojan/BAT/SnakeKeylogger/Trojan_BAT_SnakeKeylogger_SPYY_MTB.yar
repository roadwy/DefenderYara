
rule Trojan_BAT_SnakeKeylogger_SPYY_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 59 d2 9c 00 00 11 06 17 58 13 06 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}