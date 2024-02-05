
rule HackTool_Win32_Defendercontrol_S{
	meta:
		description = "HackTool:Win32/Defendercontrol.S,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 09 00 00 0a 00 "
		
	strings :
		$a_80_0 = {77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 69 73 20 63 75 72 72 65 6e 74 6c 79 20 61 63 74 69 76 65 } //windows defender is currently active  0a 00 
		$a_80_1 = {77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 69 73 20 63 75 72 72 65 6e 74 6c 79 20 6f 66 66 } //windows defender is currently off  0a 00 
		$a_80_2 = {64 69 73 61 62 6c 65 64 20 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 21 } //disabled windows defender!  0a 00 
		$a_80_3 = {66 61 69 6c 65 64 20 74 6f 20 64 69 73 61 62 6c 65 20 64 65 66 65 6e 64 65 72 } //failed to disable defender  01 00 
		$a_80_4 = {73 65 72 76 69 63 65 73 61 63 74 69 76 65 } //servicesactive  01 00 
		$a_80_5 = {74 72 75 73 74 65 64 69 6e 73 74 61 6c 6c 65 72 } //trustedinstaller  01 00 
		$a_80_6 = {73 65 64 65 62 75 67 70 72 69 76 69 6c 65 67 65 } //sedebugprivilege  01 00 
		$a_80_7 = {73 65 69 6d 70 65 72 73 6f 6e 61 74 65 70 72 69 76 69 6c 65 67 65 } //seimpersonateprivilege  01 00 
		$a_80_8 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 00 73 2d 31 2d 35 2d 31 38 } //winsta0\default  00 00 
	condition:
		any of ($a_*)
 
}