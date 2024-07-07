
rule Trojan_Win32_Pstoxci_A_MSR{
	meta:
		description = "Trojan:Win32/Pstoxci.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 64 65 6e 74 69 61 6c 46 6f 72 6d 20 69 6b 2e 50 6f 77 65 72 53 68 65 6c 6c 20 43 52 45 44 55 49 5f 49 4e 46 4f 20 43 52 45 44 55 49 5f 46 4c 41 47 53 20 43 72 65 64 55 49 52 65 74 75 72 6e 43 6f 64 65 73 20 55 73 65 72 50 77 64 20 50 53 32 45 58 45 48 6f 73 74 52 61 77 55 49 } //1 CredentialForm ik.PowerShell CREDUI_INFO CREDUI_FLAGS CredUIReturnCodes UserPwd PS2EXEHostRawUI
		$a_01_1 = {67 65 74 5f 4b 65 79 56 61 6c 75 65 20 73 65 74 5f 56 69 72 74 75 61 6c 4b 65 79 43 6f 64 65 20 67 65 74 5f 4b 65 79 43 6f 64 65 20 67 65 74 5f 53 68 69 66 74 20 67 65 74 5f 41 6c 74 20 67 65 74 5f 43 6f 6e 74 72 6f 6c 20 67 65 74 5f 43 68 61 72 73 20 73 65 74 5f 43 68 61 72 61 63 74 65 72 20 73 65 74 5f 4b 65 79 44 6f 77 6e 20 43 6f 6e 74 72 6f 6c 4b 65 79 53 74 61 74 65 73 } //1 get_KeyValue set_VirtualKeyCode get_KeyCode get_Shift get_Alt get_Control get_Chars set_Character set_KeyDown ControlKeyStates
		$a_01_2 = {50 72 65 73 73 20 61 20 6b 65 79 3f 23 30 30 30 30 38 30 3f 23 38 30 38 30 38 30 3f 23 30 30 38 30 30 30 3f 23 30 30 38 30 38 30 3f 23 38 30 30 30 38 30 3f 23 38 30 30 30 30 30 3f 23 38 30 38 30 30 30 3f 23 43 30 43 30 43 30 3f 23 30 30 46 46 30 30 3f } //1 Press a key?#000080?#808080?#008000?#008080?#800080?#800000?#808000?#C0C0C0?#00FF00?
		$a_01_3 = {3f 5e 2d 28 5b 5e 3a 20 5d 2b 29 5b 20 3a 5d 3f 28 5b 5e 3a 5d 2a 29 24 3f 54 72 75 65 3f 24 54 52 55 45 3f 46 61 6c 73 65 3f 24 46 41 4c 53 45 3f 6f 75 74 2d 73 74 72 69 6e 67 3f 73 74 72 65 61 6d 3f } //1 ?^-([^: ]+)[ :]?([^:]*)$?True?$TRUE?False?$FALSE?out-string?stream?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}