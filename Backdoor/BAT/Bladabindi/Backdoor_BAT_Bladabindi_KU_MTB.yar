
rule Backdoor_BAT_Bladabindi_KU_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 14 14 14 28 ?? 00 00 06 14 20 } //2
		$a_01_1 = {00 00 01 13 16 11 16 16 14 a2 } //2
		$a_01_2 = {00 11 16 17 14 a2 } //2
		$a_01_3 = {00 11 16 14 14 14 28 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}