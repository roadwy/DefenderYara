
rule Backdoor_Win32_Soeda_B_dha{
	meta:
		description = "Backdoor:Win32/Soeda.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 69 67 65 72 33 32 34 7b } //1 Tiger324{
		$a_01_1 = {23 72 75 6e 68 66 63 6f 72 65 2d } //1 #runhfcore-
		$a_01_2 = {23 72 75 6e 66 69 6c 65 2d } //1 #runfile-
		$a_01_3 = {57 00 65 00 20 00 70 00 72 00 6f 00 62 00 61 00 62 00 6c 00 79 00 20 00 74 00 72 00 69 00 65 00 64 00 20 00 74 00 6f 00 20 00 69 00 6e 00 6a 00 65 00 63 00 74 00 20 00 69 00 6e 00 74 00 6f 00 20 00 61 00 6e 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 We probably tried to inject into an process
		$a_01_4 = {45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 7b 00 } //1 Elevation:Administrator!new:{
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}