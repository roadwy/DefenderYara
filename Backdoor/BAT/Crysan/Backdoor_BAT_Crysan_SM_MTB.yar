
rule Backdoor_BAT_Crysan_SM_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 11 04 09 28 30 00 00 06 00 11 04 17 58 13 04 00 11 04 07 6f 92 00 00 0a 2f 0b 08 6f 93 00 00 0a 09 fe 04 2b 01 16 13 08 11 08 2d d1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}