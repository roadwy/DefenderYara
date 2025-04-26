
rule HackTool_Win32_KillSwitch_A{
	meta:
		description = "HackTool:Win32/KillSwitch.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {47 6c 6f 62 61 6c 5c 43 4f 4d 4f 44 4f 5f 4b 49 4c 4c 53 57 49 54 43 48 5f 4d 55 54 45 58 } //Global\COMODO_KILLSWITCH_MUTEX  1
		$a_80_1 = {43 4f 4d 4f 44 4f 20 4b 69 6c 6c 53 77 69 74 63 68 } //COMODO KillSwitch  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}