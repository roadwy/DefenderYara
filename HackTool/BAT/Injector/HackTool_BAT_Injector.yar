
rule HackTool_BAT_Injector{
	meta:
		description = "HackTool:BAT/Injector,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_80_0 = {54 6f 6f 6c 73 5c 56 41 43 5c 42 79 70 61 73 73 4c 4c 49 2e 64 6c 6c } //Tools\VAC\BypassLLI.dll  01 00 
		$a_80_1 = {50 72 65 73 73 20 65 6e 74 65 72 2c 20 61 6e 64 20 74 68 65 20 68 6f 6f 6b 20 77 69 6c 6c 20 62 65 20 64 6f 6e 65 21 } //Press enter, and the hook will be done!  01 00 
		$a_00_2 = {30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00 
		$a_80_3 = {4c 61 75 6e 63 68 69 6e 67 20 50 72 6f 63 65 73 73 2c 20 53 74 61 72 74 20 4d 65 74 68 6f 64 } //Launching Process, Start Method  01 00 
		$a_80_4 = {49 6e 6a 65 63 74 69 6e 67 2c 20 50 6c 65 61 73 65 20 57 61 69 74 } //Injecting, Please Wait  01 00 
		$a_80_5 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 42 79 70 61 73 73 20 4c 6f 61 64 4c 69 62 72 61 72 79 } //Do you want to Bypass LoadLibrary  01 00 
		$a_80_6 = {52 75 6e 6e 69 6e 67 20 56 41 43 20 42 79 70 61 73 73 2c 20 50 6c 65 61 73 65 20 57 61 69 74 } //Running VAC Bypass, Please Wait  01 00 
		$a_80_7 = {53 74 61 72 74 69 6e 67 20 49 6e 6a 65 63 74 69 6f 6e } //Starting Injection  01 00 
		$a_80_8 = {53 74 61 72 74 69 6e 67 20 45 6e 67 69 6e 65 3a 20 44 49 48 20 45 6e 67 69 6e 65 } //Starting Engine: DIH Engine  00 00 
	condition:
		any of ($a_*)
 
}