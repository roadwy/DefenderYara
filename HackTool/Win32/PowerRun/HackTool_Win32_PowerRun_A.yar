
rule HackTool_Win32_PowerRun_A{
	meta:
		description = "HackTool:Win32/PowerRun.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {50 6f 77 65 72 52 75 6e 20 68 61 73 20 62 65 65 6e 20 63 72 65 61 74 65 64 20 74 6f 20 72 75 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 73 20 77 69 74 68 20 45 6c 65 76 61 74 65 64 20 50 72 69 76 69 6c 65 67 65 73 } //PowerRun has been created to run Applications with Elevated Privileges  01 00 
		$a_80_1 = {53 6f 72 64 75 6d } //Sordum  00 00 
	condition:
		any of ($a_*)
 
}