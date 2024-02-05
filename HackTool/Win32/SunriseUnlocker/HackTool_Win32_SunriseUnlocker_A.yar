
rule HackTool_Win32_SunriseUnlocker_A{
	meta:
		description = "HackTool:Win32/SunriseUnlocker.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 6b 00 55 00 6e 00 6c 00 6f 00 63 00 6b 00 } //01 00 
		$a_01_1 = {61 66 66 63 73 2e 63 61 74 } //02 00 
		$a_01_2 = {46 6f 72 6d 53 75 6e 72 69 73 65 38 55 6e 6c 6f 63 6b 65 72 } //02 00 
		$a_01_3 = {53 75 6e 72 69 73 65 20 38 20 55 6e 6c 6f 63 6b 65 72 2e 65 78 65 } //02 00 
		$a_01_4 = {4d 69 63 72 6f 73 6f 66 74 2e 57 69 6e 64 6f 77 73 41 50 49 43 6f 64 65 50 61 63 6b 2e 53 68 65 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}