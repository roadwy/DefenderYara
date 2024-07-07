
rule Trojan_Win32_Qakbot_DO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {6e 64 73 33 30 77 52 2e 64 6c 6c } //1 nds30wR.dll
		$a_01_2 = {4c 41 6c 77 4c 57 49 71 75 6f } //1 LAlwLWIquo
		$a_01_3 = {52 41 64 74 56 4b 68 41 4e 70 } //1 RAdtVKhANp
		$a_01_4 = {58 6b 46 53 4e 4e 6d 70 78 } //1 XkFSNNmpx
		$a_01_5 = {5a 4d 45 70 42 44 58 57 6b 50 } //1 ZMEpBDXWkP
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win32_Qakbot_DO_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 5f 61 70 70 5f 69 6e 66 6f 5f 63 72 65 61 74 65 5f 66 72 6f 6d 5f 63 6f 6d 6d 61 6e 64 6c 69 6e 65 } //2 k_app_info_create_from_commandline
		$a_01_1 = {6b 5f 61 70 70 5f 69 6e 66 6f 5f 63 61 6e 5f 72 65 6d 6f 76 65 5f 73 75 70 70 6f 72 74 73 5f 74 79 70 65 } //2 k_app_info_can_remove_supports_type
		$a_01_2 = {6b 5f 61 63 74 69 6f 6e 5f 6d 61 70 5f 61 64 64 5f 61 63 74 69 6f 6e 5f 65 6e 74 72 69 65 73 } //2 k_action_map_add_action_entries
		$a_01_3 = {6b 5f 61 70 70 5f 69 6e 66 6f 5f 67 65 74 5f 64 65 66 61 75 6c 74 5f 66 6f 72 5f 75 72 69 5f 73 63 68 65 6d 65 } //2 k_app_info_get_default_for_uri_scheme
		$a_01_4 = {6b 5f 61 70 70 6c 69 63 61 74 69 6f 6e 5f 63 6f 6d 6d 61 6e 64 5f 6c 69 6e 65 5f 67 65 74 5f 63 77 64 } //2 k_application_command_line_get_cwd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}