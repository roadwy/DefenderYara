
rule PWS_Win32_OnLineGames_CTB{
	meta:
		description = "PWS:Win32/OnLineGames.CTB,SIGNATURE_TYPE_PEHSTR_EXT,3d 00 3d 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_02_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 47 61 6d 65 5c 90 02 28 2e 65 78 65 90 00 } //0a 00 
		$a_00_2 = {4b 69 63 6b 52 6f 6c 65 } //0a 00  KickRole
		$a_00_3 = {5c 76 65 72 63 6c 73 69 64 2e 65 78 65 } //0a 00  \verclsid.exe
		$a_00_4 = {3f 61 63 74 3d } //0a 00  ?act=
		$a_00_5 = {26 64 30 30 3d } //01 00  &d00=
		$a_00_6 = {54 65 72 6d 69 6e 61 74 65 54 68 72 65 61 64 } //01 00  TerminateThread
		$a_00_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}