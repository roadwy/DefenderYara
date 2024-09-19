
rule Trojan_BAT_SnakeLogger_AZ_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 08 8e 69 6a 5d d4 91 58 } //2
		$a_01_1 = {95 58 20 ff 00 00 00 5f 13 } //1
		$a_01_2 = {95 61 d2 9c } //1
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}