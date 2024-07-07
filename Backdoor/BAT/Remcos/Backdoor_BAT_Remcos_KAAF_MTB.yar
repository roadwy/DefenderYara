
rule Backdoor_BAT_Remcos_KAAF_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.KAAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 24 1d 11 0a 5f 91 13 18 11 18 19 62 11 18 1b 63 60 d2 13 18 11 05 11 0a 11 05 11 0a 91 11 18 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 08 32 d1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}