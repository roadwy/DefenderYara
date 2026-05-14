
rule HackTool_Win32_Patcher_SGA_AMTB{
	meta:
		description = "HackTool:Win32/Patcher.SGA!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_80_0 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 70 61 74 63 68 65 64 20 21 } //Successfully patched !  1
		$a_80_1 = {50 61 74 63 68 69 6e 67 20 66 61 69 6c 65 64 20 21 } //Patching failed !  1
		$a_80_2 = {54 68 69 73 20 50 61 74 63 68 20 77 69 6c 6c 20 72 6f 63 6b 20 50 61 72 65 74 6f 4c 6f 67 69 63 20 41 6e 74 69 2d 56 69 72 75 73 20 50 4c 55 53 20 37 2e 30 } //This Patch will rock ParetoLogic Anti-Virus PLUS 7.0  1
		$a_80_3 = {4e 65 77 20 54 69 67 65 72 20 5b 41 6f 52 45 2d 54 65 61 6d 5d } //New Tiger [AoRE-Team]  1
		$a_80_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100) >=4
 
}