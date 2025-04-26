
rule Backdoor_MacOS_Empyre_I_MTB{
	meta:
		description = "Backdoor:MacOS/Empyre.I!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 63 74 69 76 61 74 65 53 74 61 67 65 72 } //1 activateStager
		$a_01_1 = {74 65 6d 70 6c 61 74 65 44 79 6c 69 62 2e 63 } //1 templateDylib.c
		$a_03_2 = {62 61 73 65 36 34 [0-10] 65 78 65 63 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}