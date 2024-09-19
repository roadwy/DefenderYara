
rule Trojan_Win32_CleanUpLoader_DA_MTB{
	meta:
		description = "Trojan:Win32/CleanUpLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {43 69 74 69 7a 65 6e 41 70 70 6c 69 63 61 6e 74 73 50 65 72 6d 69 74 73 43 61 6d 65 72 61 73 43 61 72 73 46 72 61 75 64 } //1 CitizenApplicantsPermitsCamerasCarsFraud
		$a_81_1 = {41 75 74 6f 6d 61 74 65 64 53 75 69 63 69 64 65 } //1 AutomatedSuicide
		$a_81_2 = {53 68 61 64 6f 77 20 44 65 66 65 6e 64 65 72 } //1 Shadow Defender
		$a_81_3 = {49 6d 70 6c 65 6d 65 6e 74 69 6e 67 } //1 Implementing
		$a_81_4 = {49 73 72 61 65 6c 59 69 65 6c 64 73 } //1 IsraelYields
		$a_81_5 = {43 68 65 6d 69 63 61 6c 48 61 6e 64 6a 6f 62 73 } //1 ChemicalHandjobs
		$a_81_6 = {44 69 76 65 72 73 69 74 79 53 68 6f 70 70 65 72 63 6f 6d } //1 DiversityShoppercom
		$a_81_7 = {43 6f 70 79 20 44 65 74 61 69 6c 73 20 54 6f 20 43 6c 69 70 62 6f 61 72 64 } //1 Copy Details To Clipboard
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}