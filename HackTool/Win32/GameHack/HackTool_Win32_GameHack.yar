
rule HackTool_Win32_GameHack{
	meta:
		description = "HackTool:Win32/GameHack,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {5c 48 57 49 44 2e 74 78 74 } //\HWID.txt  1
		$a_80_1 = {50 6f 69 6e 74 42 6c 61 6e 6b 2e 65 78 65 } //PointBlank.exe  1
		$a_80_2 = {2f 2f 69 6e 64 6f 63 68 65 61 74 2e 78 79 7a } ////indocheat.xyz  1
		$a_80_3 = {54 72 61 79 49 63 6f 6e 2e 63 70 70 } //TrayIcon.cpp  1
		$a_80_4 = {50 53 41 50 49 2e 44 4c 4c } //PSAPI.DLL  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}