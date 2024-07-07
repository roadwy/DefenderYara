
rule Backdoor_Win32_Hera_A_bit{
	meta:
		description = "Backdoor:Win32/Hera.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 65 72 61 3a 3a 62 69 3a 3a 43 6f 6e 74 72 6f 6c 6c 65 72 3a 3a 52 75 6e 41 70 70 } //1 hera::bi::Controller::RunApp
		$a_01_1 = {52 75 6e 48 69 64 65 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 } //1 RunHideProcessModule
		$a_01_2 = {63 68 65 63 6b 5f 72 75 6e 5f 6d 65 6d 6f 72 79 5f 6d 6f 64 75 6c 65 5f 69 6e 74 65 72 66 61 63 65 } //1 check_run_memory_module_interface
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}