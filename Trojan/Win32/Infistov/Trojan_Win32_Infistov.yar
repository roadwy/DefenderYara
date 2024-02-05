
rule Trojan_Win32_Infistov{
	meta:
		description = "Trojan:Win32/Infistov,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 02 00 "
		
	strings :
		$a_80_0 = {4d 69 63 72 6f 73 6f 66 74 45 64 67 65 45 6c 65 76 61 74 69 6f 6e 53 65 72 76 69 63 65 } //MicrosoftEdgeElevationService  02 00 
		$a_80_1 = {41 43 54 49 4f 4e 3d 41 44 4d 49 4e 20 54 41 52 47 45 54 44 49 52 3d } //ACTION=ADMIN TARGETDIR=  02 00 
		$a_80_2 = {5c 5c 2e 5c 70 69 70 65 5c 45 78 70 6c 6f 69 74 50 69 70 65 } //\\.\pipe\ExploitPipe  01 00 
		$a_80_3 = {5c 6d 69 63 72 6f 73 6f 66 74 20 70 6c 7a } //\microsoft plz  01 00 
		$a_80_4 = {5c 6e 6f 74 65 70 61 64 2e 65 78 65 } //\notepad.exe  01 00 
		$a_80_5 = {5c 73 70 6c 77 6f 77 36 34 2e 65 78 65 } //\splwow64.exe  01 00 
		$a_80_6 = {5c 40 41 70 70 48 65 6c 70 54 6f 61 73 74 2e 70 6e 67 } //\@AppHelpToast.png  00 00 
	condition:
		any of ($a_*)
 
}