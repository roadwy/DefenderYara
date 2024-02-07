
rule HackTool_Win32_GameInject_A_MTB{
	meta:
		description = "HackTool:Win32/GameInject.A!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4e 00 69 00 71 00 6f 00 56 00 49 00 50 00 2e 00 64 00 6c 00 6c 00 } //01 00  ProgramData\Microsoft\NiqoVIP.dll
		$a_01_1 = {68 61 63 6b 20 67 61 6d 65 20 6f 6e 6c 69 6e 65 } //01 00  hack game online
		$a_01_2 = {51 75 69 74 20 41 66 74 65 72 20 49 6e 6a 65 63 74 69 6f 6e 73 } //01 00  Quit After Injections
		$a_01_3 = {44 00 6c 00 6c 00 20 00 49 00 6e 00 6a 00 65 00 63 00 74 00 65 00 64 00 } //01 00  Dll Injected
		$a_01_4 = {66 72 6d 4c 6f 67 69 6e } //01 00  frmLogin
		$a_01_5 = {4e 33 7a 20 48 61 63 6b } //01 00  N3z Hack
		$a_01_6 = {44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 49 00 6e 00 6a 00 65 00 63 00 74 00 2d 00 53 00 6f 00 75 00 72 00 63 00 65 00 } //00 00  Desktop\Inject-Source
	condition:
		any of ($a_*)
 
}