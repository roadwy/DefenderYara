
rule Trojan_Win64_Expiro_AA_MTB{
	meta:
		description = "Trojan:Win64/Expiro.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {53 70 6c 61 73 68 57 69 6e 64 6f 77 } //SplashWindow  3
		$a_80_1 = {65 26 4a 48 5a 3c 6c 77 56 6f 4e 57 6a } //e&JHZ<lwVoNWj  3
		$a_80_2 = {54 4f 7c 44 6a 69 75 } //TO|Djiu  3
		$a_80_3 = {53 68 61 70 65 43 6f 6c 6c 65 63 74 6f 72 2e 70 64 62 } //ShapeCollector.pdb  3
		$a_80_4 = {43 6f 6d 6d 61 6e 64 4c 69 6e 65 54 6f 41 72 67 76 57 } //CommandLineToArgvW  3
		$a_80_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //ShellExecuteExW  3
		$a_80_6 = {45 74 77 4c 6f 67 54 72 61 63 65 45 76 65 6e 74 } //EtwLogTraceEvent  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}