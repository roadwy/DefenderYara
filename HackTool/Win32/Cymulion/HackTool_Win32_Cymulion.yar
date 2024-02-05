
rule HackTool_Win32_Cymulion{
	meta:
		description = "HackTool:Win32/Cymulion,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_80_0 = {47 6c 6f 62 61 6c 5c 43 59 4d 55 4c 41 54 45 5f 45 44 52 } //Global\CYMULATE_EDR  02 00 
		$a_80_1 = {43 79 6d 75 6c 61 74 65 45 44 52 53 63 65 6e 61 72 69 6f 45 78 65 63 75 74 6f 72 } //CymulateEDRScenarioExecutor  01 00 
		$a_02_2 = {46 00 69 00 6c 00 65 00 73 00 5c 00 63 00 79 00 6d 00 75 00 6c 00 61 00 74 00 65 00 5c 00 65 00 64 00 72 00 5c 00 90 02 18 3c 00 43 00 79 00 6d 00 41 00 72 00 67 00 73 00 3e 00 90 00 } //01 00 
		$a_02_3 = {46 69 6c 65 73 5c 63 79 6d 75 6c 61 74 65 5c 65 64 72 5c 90 02 18 3c 43 79 6d 41 72 67 73 3e 90 00 } //01 00 
		$a_80_4 = {4e 61 74 69 76 65 52 61 6e 73 6f 6d 65 77 61 72 65 } //NativeRansomeware  00 00 
	condition:
		any of ($a_*)
 
}