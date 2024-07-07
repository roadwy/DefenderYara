
rule VirTool_Win32_Antinza_J{
	meta:
		description = "VirTool:Win32/Antinza.J,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 5f 69 64 } //1 task_id
		$a_01_1 = {63 32 5f 70 72 6f 66 69 6c 65 } //1 c2_profile
		$a_01_2 = {67 65 74 5f 74 61 73 6b 69 6e 67 } //1 get_tasking
		$a_01_3 = {74 61 73 6b 69 6e 67 5f 73 69 7a 65 } //1 tasking_size
		$a_01_4 = {67 65 74 5f 74 61 73 6b 69 6e 67 5f 72 65 73 70 6f 6e 73 65 } //1 get_tasking_response
		$a_01_5 = {41 75 74 6f 66 61 63 } //1 Autofac
		$a_01_6 = {41 67 65 6e 74 2e 64 6c 6c } //1 Agent.dll
		$a_01_7 = {73 65 74 5f 6b 65 79 6c 6f 67 73 } //1 set_keylogs
		$a_01_8 = {67 65 74 5f 73 6f 63 6b 73 } //1 get_socks
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}