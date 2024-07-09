
rule Trojan_BAT_SnakeKeylogger_D_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 91 61 28 } //2
		$a_03_1 = {8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}