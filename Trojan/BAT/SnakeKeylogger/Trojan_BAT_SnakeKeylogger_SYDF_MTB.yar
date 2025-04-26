
rule Trojan_BAT_SnakeKeylogger_SYDF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SYDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 16 08 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 08 1e 63 20 ff 00 00 00 5f d2 9c 25 18 08 20 ff 00 00 00 5f d2 9c 13 04 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}