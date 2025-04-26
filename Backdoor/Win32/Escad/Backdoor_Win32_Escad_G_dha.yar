
rule Backdoor_Win32_Escad_G_dha{
	meta:
		description = "Backdoor:Win32/Escad.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {7a 7a 25 64 2e 62 61 74 } //1 zz%d.bat
		$a_02_1 = {64 65 6c 20 22 [0-10] 69 66 20 65 78 69 73 74 20 22 } //1
		$a_02_2 = {6d 63 75 2e 69 6e 66 [0-05] 52 65 67 69 73 74 65 72 [0-10] 6d 63 75 2e 64 6c 6c [0-10] 72 62 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Backdoor_Win32_Escad_G_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {7a 7a 25 64 2e 62 61 74 } //1 zz%d.bat
		$a_02_1 = {64 65 6c 20 22 [0-10] 69 66 20 65 78 69 73 74 20 22 } //1
		$a_02_2 = {6d 63 75 2e 69 6e 66 [0-05] 52 65 67 69 73 74 65 72 [0-10] 6d 63 75 2e 64 6c 6c [0-10] 72 62 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}