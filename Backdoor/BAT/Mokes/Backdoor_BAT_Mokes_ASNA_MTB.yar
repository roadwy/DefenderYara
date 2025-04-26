
rule Backdoor_BAT_Mokes_ASNA_MTB{
	meta:
		description = "Backdoor:BAT/Mokes.ASNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 04 2b 22 06 09 8f 21 00 00 01 25 47 07 11 04 91 09 1f 1e 5d 58 d2 61 d2 52 09 17 58 0d 11 04 17 58 08 5d 13 04 09 06 8e 69 32 d8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}