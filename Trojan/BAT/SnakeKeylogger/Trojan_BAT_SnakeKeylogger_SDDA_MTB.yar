
rule Trojan_BAT_SnakeKeylogger_SDDA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SDDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e 04 00 00 04 8e 69 fe 04 0d 09 2d d9 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}