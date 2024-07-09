
rule Backdoor_BAT_Bladabindi_MBKL_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MBKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 06 09 28 ?? 00 00 0a 22 00 00 20 41 5a 22 00 00 82 42 58 28 ?? 00 00 0a 6c 28 ?? 00 00 0a b7 28 ?? 00 00 0a 9d 02 6f ?? 00 00 06 13 06 11 06 11 06 6f ?? 00 00 0a 06 09 93 } //1
		$a_01_1 = {36 37 35 34 36 31 34 30 30 32 66 65 } //1 6754614002fe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}