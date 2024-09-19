
rule Trojan_BAT_SnakeKeyLogger_RDBJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeyLogger.RDBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f 95 d2 13 12 11 10 11 12 61 13 13 } //2
		$a_01_1 = {11 07 11 0f d4 11 13 20 ff 00 00 00 5f d2 9c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}