
rule Trojan_Win64_KillAV_DA_MTB{
	meta:
		description = "Trojan:Win64/KillAV.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,38 00 38 00 07 00 00 "
		
	strings :
		$a_81_0 = {41 56 5f 4b 49 4c 4c 45 52 } //50 AV_KILLER
		$a_81_1 = {73 63 2e 65 78 65 20 63 72 65 61 74 65 } //1 sc.exe create
		$a_81_2 = {73 63 2e 65 78 65 20 73 74 61 72 74 20 } //1 sc.exe start 
		$a_81_3 = {2e 5c 54 72 75 65 53 69 67 68 74 } //1 .\TrueSight
		$a_81_4 = {4d 73 4d 70 45 6e 67 2e 65 78 65 } //1 MsMpEng.exe
		$a_81_5 = {44 72 69 76 65 72 20 66 69 6c 65 20 63 72 65 61 74 65 64 } //1 Driver file created
		$a_81_6 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 74 65 72 6d 69 6e 61 74 65 64 20 70 72 6f 63 65 73 73 } //1 Successfully terminated process
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=56
 
}