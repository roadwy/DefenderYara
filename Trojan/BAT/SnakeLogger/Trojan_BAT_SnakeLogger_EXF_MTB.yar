
rule Trojan_BAT_SnakeLogger_EXF_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.EXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 15 1f 10 5d 93 11 17 61 11 15 20 ff 00 00 00 5d d1 61 d1 } //1
		$a_03_1 = {06 07 02 07 18 5a 18 90 01 05 1f 10 90 01 05 9c 07 17 58 0b 90 00 } //1
		$a_81_2 = {46 75 63 6b 4d 69 63 72 6f 73 6f 66 74 31 32 33 } //1 FuckMicrosoft123
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}