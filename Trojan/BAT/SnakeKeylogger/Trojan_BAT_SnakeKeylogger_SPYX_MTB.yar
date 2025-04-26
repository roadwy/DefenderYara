
rule Trojan_BAT_SnakeKeylogger_SPYX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPYX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 08 11 ?? 17 58 20 ?? ?? ?? 00 5d 91 09 58 09 5d 59 d2 9c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}