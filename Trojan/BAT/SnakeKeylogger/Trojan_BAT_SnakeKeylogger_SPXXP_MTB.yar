
rule Trojan_BAT_SnakeKeylogger_SPXXP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPXXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 15 91 61 07 11 12 17 58 20 ?? ?? ?? 00 5d 91 08 58 08 5d 59 d2 9c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}