
rule HackTool_Win64_Herpaderping_B{
	meta:
		description = "HackTool:Win64/Herpaderping.B,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_80_0 = {50 72 6f 63 65 73 73 48 65 72 70 61 64 65 72 70 69 6e 67 2e 70 64 62 } //ProcessHerpaderping.pdb  0a 00 
		$a_80_1 = {50 72 6f 63 65 73 73 20 48 65 72 70 61 64 65 72 70 69 6e 67 20 54 6f 6f 6c } //Process Herpaderping Tool  0a 00 
		$a_80_2 = {50 72 6f 63 65 73 73 48 65 72 70 61 64 65 72 70 69 6e 67 2e 65 78 65 20 53 6f 75 72 63 65 46 69 6c 65 20 54 61 72 67 65 74 46 69 6c 65 } //ProcessHerpaderping.exe SourceFile TargetFile  0a 00 
		$a_80_3 = {50 72 6f 63 65 73 73 20 48 65 72 70 61 64 65 72 70 20 46 61 69 6c 65 64 } //Process Herpaderp Failed  0a 00 
		$a_80_4 = {50 72 6f 63 65 73 73 20 48 65 72 70 61 64 65 72 70 20 53 75 63 63 65 65 64 65 64 } //Process Herpaderp Succeeded  05 00 
		$a_80_5 = {68 69 64 69 6e 67 20 6f 72 69 67 69 6e 61 6c 20 62 79 74 65 73 20 61 6e 64 20 72 65 74 61 69 6e 69 6e 67 20 61 6e 79 20 73 69 67 6e 61 74 75 72 65 } //hiding original bytes and retaining any signature  05 00 
		$a_80_6 = {2d 75 2c 2d 2d 64 6f 2d 6e 6f 74 2d 66 6c 75 73 68 2d 66 69 6c 65 } //-u,--do-not-flush-file  00 00 
	condition:
		any of ($a_*)
 
}