
rule Backdoor_BAT_Bladabindi_SM_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 1f 1a 0b 1f 4e 0c 28 90 01 0e 6f 90 01 04 0d 09 72 90 01 09 13 04 73 90 01 04 13 05 11 04 17 8d 90 01 04 25 16 11 05 6f 90 01 04 a2 28 90 01 04 26 2a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Backdoor_BAT_Bladabindi_SM_MTB_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 06 07 06 93 02 7b 03 00 00 04 04 20 3b ad 23 26 20 ca 4e a1 27 61 66 66 20 d9 d0 64 d1 61 65 65 20 d5 83 e8 4d 61 66 20 e4 3b 46 be 61 66 20 16 8b 48 23 61 5f 91 04 60 61 d1 9d } //2
		$a_81_1 = {33 33 33 33 33 33 33 33 2e 65 78 65 } //2 33333333.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}