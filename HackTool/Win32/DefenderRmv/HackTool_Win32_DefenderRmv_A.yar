
rule HackTool_Win32_DefenderRmv_A{
	meta:
		description = "HackTool:Win32/DefenderRmv.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {44 65 66 65 6e 64 65 72 20 52 65 6d 6f 76 65 72 } //Defender Remover  01 00 
		$a_80_1 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 72 75 6e 2e 62 61 74 22 } //RunProgram="run.bat"  01 00 
		$a_00_2 = {3b 63 6f 70 79 20 2f 62 20 63 6f 6d 70 69 6c 65 72 2e 6d 70 6d 20 2b 20 63 6f 6e 66 69 67 2e 74 78 74 20 2b 20 72 65 62 64 2e 37 7a 20 67 61 6c 6c 65 72 79 5f 6d 70 6d 2e 65 78 65 3b } //00 00  ;copy /b compiler.mpm + config.txt + rebd.7z gallery_mpm.exe;
	condition:
		any of ($a_*)
 
}