
rule Backdoor_BAT_Crysan_SL_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 1f 09 5d 16 fe 01 13 05 11 05 2c 0d 06 11 04 06 11 04 91 1f 5e 61 b4 9c 00 00 11 04 17 d6 13 04 11 04 09 31 d9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Backdoor_BAT_Crysan_SL_MTB_2{
	meta:
		description = "Backdoor:BAT/Crysan.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 e4 03 00 00 fe 1c 29 00 00 01 58 28 14 00 00 0a 06 20 fd ff ff ff fe 1c 29 00 00 01 58 58 0a 06 7e 11 00 00 04 28 15 00 00 0a 32 d3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}