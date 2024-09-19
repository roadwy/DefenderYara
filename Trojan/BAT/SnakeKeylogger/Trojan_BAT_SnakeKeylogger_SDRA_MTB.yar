
rule Trojan_BAT_SnakeKeylogger_SDRA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SDRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 06 7e 04 00 00 04 06 91 04 06 04 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e 04 00 00 04 8e 69 fe 04 0b 07 2d d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}