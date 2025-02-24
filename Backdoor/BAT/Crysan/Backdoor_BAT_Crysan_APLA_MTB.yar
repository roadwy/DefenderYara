
rule Backdoor_BAT_Crysan_APLA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.APLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 02 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 05 11 05 2d df } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}