
rule Backdoor_BAT_Warhawk_PAFQ_MTB{
	meta:
		description = "Backdoor:BAT/Warhawk.PAFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 06 8f ?? ?? ?? ?? 25 47 11 04 11 06 1f 10 5d 91 61 d2 52 11 06 17 58 13 06 11 06 11 05 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}