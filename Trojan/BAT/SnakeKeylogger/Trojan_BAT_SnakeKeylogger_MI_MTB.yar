
rule Trojan_BAT_SnakeKeylogger_MI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 18 5b 07 11 04 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 11 04 18 58 13 04 11 04 08 32 df 09 13 05 de 42 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}