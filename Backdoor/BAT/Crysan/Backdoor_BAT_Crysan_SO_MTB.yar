
rule Backdoor_BAT_Crysan_SO_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 35 00 00 06 0a dd 09 00 00 00 26 dd 00 00 00 00 06 2c eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}