
rule Trojan_BAT_SnakeKeylogger_PHJH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PHJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 1d 11 09 11 22 11 27 61 19 11 1a 58 61 11 2f 61 d2 9c 17 11 09 58 13 09 11 27 13 1a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}