
rule Backdoor_Win32_Quisset_A{
	meta:
		description = "Backdoor:Win32/Quisset.A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {05 80 d4 7d ee 6a 00 83 d1 02 68 80 96 98 00 51 50 e8 } //10
		$a_00_1 = {2e 70 68 70 3f 6d 61 63 3d } //2 .php?mac=
		$a_00_2 = {2e 64 65 6c 65 74 65 64 } //1 .deleted
		$a_00_3 = {64 65 6c 6f 6e 6c 79 } //1 delonly
		$a_00_4 = {73 74 61 72 74 75 72 6c } //1 starturl
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=13
 
}