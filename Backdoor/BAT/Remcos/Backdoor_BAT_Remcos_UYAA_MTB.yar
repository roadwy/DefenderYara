
rule Backdoor_BAT_Remcos_UYAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.UYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 1b 00 7e ?? 00 00 04 06 7e ?? 00 00 04 06 91 7e ?? 00 00 04 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b 07 2d d7 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}