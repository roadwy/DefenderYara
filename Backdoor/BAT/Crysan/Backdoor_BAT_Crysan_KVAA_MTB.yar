
rule Backdoor_BAT_Crysan_KVAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.KVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 18 5d 3a 09 00 00 00 06 02 58 0a 38 04 00 00 00 06 02 59 0a 07 17 58 0b 07 03 32 e3 } //2
		$a_01_1 = {04 1f 0a 3b 0d 00 00 00 04 1f 14 3b 0b 00 00 00 38 0c 00 00 00 02 03 5a 04 5b 2a 02 03 58 04 5a 2a 02 03 59 04 5a 2a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}