
rule Worm_Win32_Stobot_A{
	meta:
		description = "Worm:Win32/Stobot.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 72 43 5f 53 54 4f 5f 42 6f 74 6e 65 74 5f 4d 6f 64 75 6c 65 5f 53 74 61 62 6c 65 } //3 irC_STO_Botnet_Module_Stable
		$a_01_1 = {75 64 70 66 6c 6f 6f 64 73 74 61 72 74 } //2 udpfloodstart
		$a_01_2 = {6d 5f 64 65 6c 65 74 65 62 6f 74 5f 70 61 73 73 77 6f 72 64 5f 65 72 72 6f 72 } //2 m_deletebot_password_error
		$a_01_3 = {63 6f 6d 6d 61 6e 64 5f 73 79 6e 66 6c 6f 6f 64 } //2 command_synflood
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=5
 
}