
rule VirTool_Win32_Injector_SBR_MSR{
	meta:
		description = "VirTool:Win32/Injector.SBR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 65 63 20 62 79 70 61 73 73 } //01 00 
		$a_01_1 = {67 69 74 65 65 2e 63 6f 6d } //01 00 
		$a_00_2 = {41 00 50 00 50 00 4c 00 49 00 43 00 41 00 54 00 49 00 4f 00 4e 00 20 00 44 00 41 00 54 00 41 00 5c 00 53 00 45 00 43 00 55 00 52 00 49 00 54 00 59 00 2e 00 44 00 4c 00 4c 00 } //01 00 
		$a_01_3 = {61 63 71 75 69 72 65 20 63 72 65 64 65 6e 74 69 61 6c 73 } //00 00 
	condition:
		any of ($a_*)
 
}