
rule Trojan_Win32_Danabot_SA_MSR{
	meta:
		description = "Trojan:Win32/Danabot.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 69 6e 6f 72 6e 54 68 65 73 65 52 6f 6f 67 6c 65 69 } //1 MinornTheseRooglei
		$a_01_1 = {65 6e 6f 77 68 6e 65 77 63 38 61 72 65 35 68 } //1 enowhnewc8are5h
		$a_03_2 = {61 6c 77 61 72 65 29 2c 32 30 30 39 2c 74 68 65 6c 55 [0-01] 69 63 65 6e 73 65 73 [0-01] 6f 72 65 64 51 4e } //1
		$a_01_3 = {77 68 65 6e 71 75 62 57 69 6e 64 6f 77 73 2d 6f 6e 6c 79 49 70 72 6f 63 65 73 73 } //1 whenqubWindows-onlyIprocess
		$a_01_4 = {77 68 65 72 68 77 23 40 68 72 65 2e 70 64 62 } //1 wherhw#@hre.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}