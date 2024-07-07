
rule Backdoor_BAT_Bladabindi_MBJS_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MBJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 09 16 09 8e b7 6f 90 01 01 00 00 0a 26 11 05 90 00 } //1
		$a_01_1 = {45 00 47 00 5a 00 63 00 31 00 49 00 44 00 35 00 58 00 30 00 58 00 6f 00 43 00 58 00 71 00 68 00 6e 00 51 00 58 00 57 00 32 00 77 00 6d 00 76 00 58 00 57 00 46 00 39 00 4d 00 56 00 72 00 41 00 59 00 43 00 55 00 4c 00 } //1 EGZc1ID5X0XoCXqhnQXW2wmvXWF9MVrAYCUL
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}