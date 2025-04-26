
rule Backdoor_Win32_Buterat_C_bit{
	meta:
		description = "Backdoor:Win32/Buterat.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 00 69 00 75 00 6c 00 69 00 61 00 6e 00 67 00 62 00 61 00 6f 00 } //1 liuliangbao
		$a_01_1 = {53 00 43 00 43 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 64 00 61 00 74 00 } //1 SCConfig.dat
		$a_01_2 = {43 00 46 00 47 00 55 00 70 00 64 00 61 00 74 00 65 00 } //1 CFGUpdate
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}