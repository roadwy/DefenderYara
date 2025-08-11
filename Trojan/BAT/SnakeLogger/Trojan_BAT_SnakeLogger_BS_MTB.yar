
rule Trojan_BAT_SnakeLogger_BS_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 11 03 59 20 ff 00 00 00 5f d2 13 } //3
		$a_01_1 = {fe ff ff 11 02 66 d2 13 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}