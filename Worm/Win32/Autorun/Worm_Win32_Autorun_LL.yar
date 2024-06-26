
rule Worm_Win32_Autorun_LL{
	meta:
		description = "Worm:Win32/Autorun.LL,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 } //0a 00  [AutoRun]
		$a_00_1 = {5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //0a 00  \autorun.inf
		$a_00_2 = {73 74 72 50 61 73 73 77 64 54 6f 52 65 63 6f 76 65 72 } //0a 00  strPasswdToRecover
		$a_01_3 = {65 00 6e 00 43 00 72 00 59 00 70 00 74 00 65 00 44 00 } //0a 00  enCrYpteD
		$a_01_4 = {44 00 65 00 43 00 72 00 59 00 70 00 74 00 65 00 44 00 } //0a 00  DeCrYpteD
		$a_00_5 = {5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //00 00  \svchost32.exe
	condition:
		any of ($a_*)
 
}