
rule Backdoor_BAT_Bladabindi_ASCB_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ASCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 38 ?? 00 00 00 0d 38 ?? 00 00 00 07 08 11 05 1e 62 11 04 60 d1 9d 38 ?? 00 00 00 0b 38 ?? 00 00 00 08 17 58 0c 38 ?? 00 00 00 0a 38 ?? 00 00 00 08 07 8e 69 38 ?? 00 00 00 28 ?? 00 00 0a 2a } //4
		$a_01_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 38 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}