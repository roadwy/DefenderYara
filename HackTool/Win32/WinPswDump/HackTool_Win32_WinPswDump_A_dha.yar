
rule HackTool_Win32_WinPswDump_A_dha{
	meta:
		description = "HackTool:Win32/WinPswDump.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 73 61 73 73 2e 65 78 65 } //1 lsass.exe
		$a_01_1 = {5b 78 5d 20 45 72 72 6f 72 3a 20 43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 20 68 61 6e 64 6c 65 20 74 6f 20 6c 73 61 73 73 20 70 72 6f 63 65 73 73 } //1 [x] Error: Could not open handle to lsass process
		$a_01_2 = {5b 78 5d 20 45 72 72 6f 72 3a 20 43 6f 75 6c 64 20 6e 6f 74 20 66 69 6e 64 20 61 6c 6c 20 44 4c 4c 27 73 20 69 6e 20 4c 53 41 53 53 } //1 [x] Error: Could not find all DLL's in LSASS
		$a_01_3 = {5b 78 5d 20 45 72 72 6f 72 3a 20 43 6f 75 6c 64 20 6e 6f 74 20 66 69 6e 64 20 63 72 65 64 65 6e 74 69 61 6c 73 20 69 6e 20 6c 73 61 73 73 } //1 [x] Error: Could not find credentials in lsass
		$a_01_4 = {67 65 74 5f 6c 73 61 73 73 5f 65 78 65 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 47 65 74 57 69 6e 50 73 77 2e 70 64 62 } //1 get_lsass_exe\x64\Release\GetWinPsw.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}