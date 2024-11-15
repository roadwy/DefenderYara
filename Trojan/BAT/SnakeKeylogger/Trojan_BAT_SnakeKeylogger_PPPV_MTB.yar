
rule Trojan_BAT_SnakeKeylogger_PPPV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.PPPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 19 00 02 08 7e ?? ?? ?? ?? 08 91 03 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e ?? ?? ?? ?? 8e 69 fe 04 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}