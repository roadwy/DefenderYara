
rule Trojan_BAT_SnakeKeylogger_SSUB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SSUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 8f 4d 00 00 01 25 47 04 20 ff 00 00 00 5f d2 61 d2 52 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d de } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}