
rule Trojan_BAT_MassLogger_ABQA_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.ABQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 0b 94 13 0c 00 11 04 11 0c 19 5a 11 0c 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 00 11 0b 17 58 13 0b 11 0b 11 0a 8e 69 32 cc } //3
		$a_01_1 = {06 11 06 11 06 1f 11 5a 11 06 18 62 61 20 aa 00 00 00 60 9e 00 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d d7 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}