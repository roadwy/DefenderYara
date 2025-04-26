
rule Backdoor_BAT_Remcos_UXAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.UXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 1f 00 7e ?? 00 00 04 11 06 7e ?? 00 00 04 11 06 91 20 d1 01 00 00 59 d2 9c 00 11 06 17 58 13 06 11 06 7e ?? 00 00 04 8e 69 fe 04 13 07 11 07 2d d0 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}