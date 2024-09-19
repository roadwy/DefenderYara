
rule Backdoor_BAT_Crysan_SL_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 e4 03 00 00 fe 1c 29 00 00 01 58 28 14 00 00 0a 06 20 fd ff ff ff fe 1c 29 00 00 01 58 58 0a 06 7e 11 00 00 04 28 15 00 00 0a 32 d3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}