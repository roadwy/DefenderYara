
rule Backdoor_BAT_NanoBot_PA_MTB{
	meta:
		description = "Backdoor:BAT/NanoBot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 00 4f 00 4e 00 54 00 5f 00 4d 00 55 00 54 00 41 00 54 00 45 00 } //1 DONT_MUTATE
		$a_03_1 = {8e 69 17 da 17 d8 13 ?? 16 13 ?? 2b } //1
		$a_03_2 = {8e 69 5d 91 09 11 ?? 09 8e 69 5d 91 61 [0-10] 17 d6 [0-08] 8e 69 5d 91 da 20 [0-08] d6 20 [0-08] 5d b4 9c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}