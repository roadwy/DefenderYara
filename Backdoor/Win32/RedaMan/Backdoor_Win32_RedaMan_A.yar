
rule Backdoor_Win32_RedaMan_A{
	meta:
		description = "Backdoor:Win32/RedaMan.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 66 6f 67 68 6a 76 76 68 74 6d 77 69 63 73 70 } //1 vfoghjvvhtmwicsp
		$a_01_1 = {70 6e 65 76 64 74 71 76 62 68 62 63 72 6d 65 67 70 } //1 pnevdtqvbhbcrmegp
		$a_01_2 = {77 75 64 65 6d 65 64 69 6c } //1 wudemedil
		$a_01_3 = {62 00 6e 00 63 00 6f 00 62 00 6a 00 61 00 70 00 69 00 2e 00 64 00 6c 00 6c 00 } //1 bncobjapi.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}