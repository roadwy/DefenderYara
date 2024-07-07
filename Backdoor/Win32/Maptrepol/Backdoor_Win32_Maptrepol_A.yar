
rule Backdoor_Win32_Maptrepol_A{
	meta:
		description = "Backdoor:Win32/Maptrepol.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 00 73 00 5f 00 63 00 6f 00 6d 00 5f 00 68 00 7a 00 79 00 66 00 5f 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5f 00 61 00 70 00 70 00 5f 00 63 00 6f 00 6d 00 5f 00 31 00 2e 00 30 00 } //2 ms_com_hzyf_microsoft_app_com_1.0
		$a_01_1 = {63 00 6c 00 61 00 73 00 5f 00 68 00 7a 00 79 00 5f 00 61 00 70 00 74 00 5f 00 77 00 69 00 6e 00 6d 00 6d 00 74 00 5f 00 78 00 5f 00 30 00 2e 00 30 00 2e 00 30 00 31 00 } //2 clas_hzy_apt_winmmt_x_0.0.01
		$a_01_2 = {77 72 6c 63 6b 2e 63 61 62 } //1 wrlck.cab
		$a_01_3 = {25 6c 73 6d 73 61 74 74 72 69 62 33 32 5f 25 73 5f 69 } //1 %lsmsattrib32_%s_i
		$a_01_4 = {77 6e 64 70 6c 79 72 2e 63 61 62 } //1 wndplyr.cab
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}