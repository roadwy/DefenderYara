
rule Backdoor_BAT_Crysan_AYWA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AYWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 03 11 04 11 03 91 11 01 11 03 11 01 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}