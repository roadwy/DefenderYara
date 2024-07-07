
rule Backdoor_BAT_Bladabindi_ARAC_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0a 38 90 01 04 17 11 08 58 13 08 11 08 08 fe 04 90 00 } //2
		$a_01_1 = {35 73 38 73 38 51 76 } //2 5s8s8Qv
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Backdoor_BAT_Bladabindi_ARAC_MTB_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 91 13 07 08 17 58 20 ff 00 00 00 5f 0c 09 06 08 91 58 20 ff 00 00 00 5f 0d 06 08 09 28 0a 00 00 06 07 11 04 11 07 06 06 08 91 06 09 91 58 20 ff 00 00 00 5f 91 61 d2 9c 11 06 17 58 13 06 11 06 11 05 8e 69 32 b6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}