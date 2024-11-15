
rule Backdoor_BAT_Crysan_YLAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.YLAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 12 04 28 ?? 00 00 0a 07 06 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 0b 11 04 2c 06 09 28 ?? 00 00 0a dc } //3
		$a_03_1 = {08 18 25 2c 0f 58 1b 2c 05 0c 16 2d b7 08 06 6f ?? 00 00 0a 16 2d eb 32 ad 07 6f ?? 00 00 0a 2a 28 ?? 00 00 0a 38 ?? ff ff ff 02 38 ?? ff ff ff 6f ?? 00 00 0a 38 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}