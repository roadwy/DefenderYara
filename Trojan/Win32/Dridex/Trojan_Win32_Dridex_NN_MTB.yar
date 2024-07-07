
rule Trojan_Win32_Dridex_NN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {45 53 54 41 50 50 20 45 5f } //1 ESTAPP E_
		$a_81_1 = {65 6c 66 20 45 58 } //1 elf EX
		$a_81_2 = {75 6e 64 65 72 43 71 61 6e 35 } //1 underCqan5
		$a_81_3 = {46 50 4f 4c 4d 2e 70 64 62 } //1 FPOLM.pdb
		$a_81_4 = {53 75 72 67 65 6f 6e 73 48 7a } //1 SurgeonsHz
		$a_81_5 = {70 66 72 61 6e 6b 62 72 6f 77 73 65 72 73 2e 72 75 6e 41 } //1 pfrankbrowsers.runA
		$a_81_6 = {73 75 70 70 6f 72 74 2e 4c 6d 6f 6e 74 68 6c 79 2c 6d 6f 66 66 6c 69 6e 65 61 6e 64 68 65 6c 70 } //1 support.Lmonthly,mofflineandhelp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}