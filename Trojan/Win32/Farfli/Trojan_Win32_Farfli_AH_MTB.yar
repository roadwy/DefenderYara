
rule Trojan_Win32_Farfli_AH_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 46 43 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 41 70 70 49 44 2e 4e 6f 56 65 72 73 69 6f 6e } //3 MFCApplication1.AppID.NoVersion
		$a_01_1 = {66 75 63 6b 79 6f 75 } //3 fuckyou
		$a_01_2 = {55 73 65 72 73 5c 4d 52 4b } //3 Users\MRK
		$a_01_3 = {38 30 38 38 77 77 63 32 32 30 33 31 38 76 73 32 30 32 32 4d 46 43 } //3 8088wwc220318vs2022MFC
		$a_01_4 = {4d 46 43 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 70 64 62 } //3 MFCApplication1.pdb
		$a_01_5 = {53 6c 65 65 70 43 6f 6e 64 69 74 69 6f 6e 56 61 72 69 61 62 6c 65 43 53 } //3 SleepConditionVariableCS
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}