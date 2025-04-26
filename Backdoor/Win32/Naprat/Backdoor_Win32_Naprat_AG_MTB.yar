
rule Backdoor_Win32_Naprat_AG_MTB{
	meta:
		description = "Backdoor:Win32/Naprat.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 67 00 69 00 6e 00 } //2 Login
		$a_01_1 = {7b 00 48 00 6f 00 6d 00 65 00 7d 00 2b 00 7b 00 45 00 6e 00 64 00 7d 00 } //2 {Home}+{End}
		$a_01_2 = {50 00 2e 00 65 00 78 00 65 00 } //2 P.exe
		$a_01_3 = {74 78 74 50 61 73 73 77 6f 72 64 } //2 txtPassword
		$a_01_4 = {73 79 73 74 65 6d 33 32 5c 77 6d 70 2e 6f 63 61 } //2 system32\wmp.oca
		$a_01_5 = {59 75 6e 49 6f 51 77 4a } //2 YunIoQwJ
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}