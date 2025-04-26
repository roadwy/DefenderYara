
rule Backdoor_BAT_Mokes_AHNA_MTB{
	meta:
		description = "Backdoor:BAT/Mokes.AHNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 07 8e 69 5d 91 13 05 06 11 04 8f ?? 00 00 01 25 47 11 05 1e 5a 20 00 01 00 00 5d d2 61 d2 52 08 11 04 06 11 04 91 11 04 1f 0e 5a 20 00 01 00 00 5d 59 11 05 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 32 b9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}