
rule Worm_Win32_Autorun_ZI{
	meta:
		description = "Worm:Win32/Autorun.ZI,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //02 00  \autorun.inf
		$a_01_1 = {54 65 73 74 69 6e 67 2e 65 78 65 } //01 00  Testing.exe
		$a_01_2 = {50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 5c 44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //01 00  Policies\System\DisableRegistryTools
		$a_01_3 = {77 69 6e 6d 67 6d 74 73 3a 5c 5c 2e 5c 72 6f 6f 74 5c 64 65 66 61 75 6c 74 3a 53 79 73 74 65 6d 52 65 73 74 6f 72 65 } //02 00  winmgmts:\\.\root\default:SystemRestore
		$a_01_4 = {69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 } //02 00  ion\Policies\System /v DisableTaskMgr /t REG_DWORD
		$a_01_5 = {72 61 70 69 64 73 68 61 72 65 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 75 70 6c 6f 61 64 2e 63 67 69 3f 72 73 75 70 6c 6f 61 64 69 64 3d } //00 00  rapidshare.com/cgi-bin/upload.cgi?rsuploadid=
	condition:
		any of ($a_*)
 
}