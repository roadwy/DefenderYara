
rule VirTool_BAT_AntiVm_GG_MTB{
	meta:
		description = "VirTool:BAT/AntiVm.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 0a 00 00 0a 00 "
		
	strings :
		$a_80_0 = {49 6e 6a 65 63 74 } //Inject  0a 00 
		$a_80_1 = {5c 52 65 67 41 73 6d 2e 65 78 65 } //\RegAsm.exe  0a 00 
		$a_80_2 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 33 20 26 20 44 65 6c 20 22 } ///C choice /C Y /N /D Y /T 3 & Del "  01 00 
		$a_80_3 = {70 6f 77 65 72 73 68 65 6c 6c } //powershell  01 00 
		$a_80_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  01 00 
		$a_80_5 = {44 72 6f 70 } //Drop  01 00 
		$a_80_6 = {76 6d 77 61 72 65 } //vmware  01 00 
		$a_80_7 = {71 65 6d 75 } //qemu  01 00 
		$a_80_8 = {56 49 52 54 55 41 4c 42 4f 58 } //VIRTUALBOX  01 00 
		$a_80_9 = {76 62 6f 78 } //vbox  00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_AntiVm_GG_MTB_2{
	meta:
		description = "VirTool:BAT/AntiVm.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0a 00 00 0a 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 } //schtasks  01 00 
		$a_80_1 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //Select * from AntivirusProduct  01 00 
		$a_80_2 = {76 6d 77 61 72 65 } //vmware  01 00 
		$a_80_3 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //SbieDll.dll  01 00 
		$a_80_4 = {56 49 52 54 55 41 4c 42 4f 58 } //VIRTUALBOX  01 00 
		$a_80_5 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //Select * from Win32_ComputerSystem  01 00 
		$a_80_6 = {50 61 73 74 65 62 69 6e } //Pastebin  01 00 
		$a_80_7 = {25 61 70 70 64 61 74 61 25 } //%appdata%  01 00 
		$a_80_8 = {5c 6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //\nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS  01 00 
		$a_80_9 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  00 00 
	condition:
		any of ($a_*)
 
}