
rule Backdoor_BAT_Bladabindi_ABT_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {07 02 6f 24 ?? ?? 0a 0a de 0a 07 2c 06 07 6f ?? ?? ?? 0a dc 03 72 ?? ?? ?? 70 04 28 ?? ?? ?? 0a 06 28 ?? ?? ?? 0a 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 03 72 ?? ?? ?? 70 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 de 13 } //5
		$a_01_1 = {67 65 74 5f 43 75 72 72 65 6e 74 44 69 72 65 63 74 6f 72 79 } //1 get_CurrentDirectory
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {52 75 57 4c 70 4b 75 78 44 68 66 41 } //1 RuWLpKuxDhfA
		$a_01_4 = {57 41 4f 58 52 4b 46 69 56 71 56 54 } //1 WAOXRKFiVqVT
		$a_01_5 = {2f 00 43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 33 00 20 00 26 00 20 00 44 00 65 00 6c 00 } //1 /C choice /C Y /N /D Y /T 3 & Del
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}