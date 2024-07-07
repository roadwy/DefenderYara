
rule Backdoor_BAT_Crysan_SP_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f 90 01 03 0a 11 04 13 05 16 2d d7 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}