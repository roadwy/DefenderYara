
rule Trojan_BAT_SnakeLogger_BF_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {95 13 13 11 12 11 13 61 13 14 11 05 11 11 11 14 d2 9c 11 07 17 58 13 07 00 11 07 6e 11 05 8e 69 6a fe 04 } //4
		$a_01_1 = {95 58 20 ff 00 00 00 5f 13 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}