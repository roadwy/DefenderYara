
rule Backdoor_Win32_KaziBora_A_dha{
	meta:
		description = "Backdoor:Win32/KaziBora.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 79 63 6d 65 6e 74 65 63 } //6 Sycmentec
		$a_02_1 = {14 88 77 66 c7 [0-03] 08 02 00 00 } //6
		$a_00_2 = {03 77 66 55 } //2 眃啦
		$a_00_3 = {01 77 66 55 } //2 省啦
		$a_00_4 = {11 88 77 66 } //2
	condition:
		((#a_01_0  & 1)*6+(#a_02_1  & 1)*6+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=6
 
}