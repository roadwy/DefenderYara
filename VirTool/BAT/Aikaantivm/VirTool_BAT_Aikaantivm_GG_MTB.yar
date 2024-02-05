
rule VirTool_BAT_Aikaantivm_GG_MTB{
	meta:
		description = "VirTool:BAT/Aikaantivm.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,49 00 49 00 0c 00 00 0a 00 "
		
	strings :
		$a_80_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  0a 00 
		$a_80_1 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //Select * from Win32_ComputerSystem  0a 00 
		$a_80_2 = {6d 69 63 72 6f 73 6f 66 74 20 63 6f 72 70 6f 72 61 74 69 6f 6e } //microsoft corporation  0a 00 
		$a_81_3 = {56 49 52 54 55 41 4c } //0a 00 
		$a_80_4 = {76 6d 77 61 72 65 } //vmware  0a 00 
		$a_80_5 = {56 69 72 74 75 61 6c 42 6f 78 } //VirtualBox  0a 00 
		$a_80_6 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //SbieDll.dll  01 00 
		$a_80_7 = {63 6d 64 76 72 74 33 32 2e 64 6c 6c } //cmdvrt32.dll  01 00 
		$a_80_8 = {53 78 49 6e 2e 64 6c 6c } //SxIn.dll  01 00 
		$a_80_9 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //WriteProcessMemory  01 00 
		$a_80_10 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //NtUnmapViewOfSection  01 00 
		$a_80_11 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_Aikaantivm_GG_MTB_2{
	meta:
		description = "VirTool:BAT/Aikaantivm.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,40 00 40 00 0c 00 00 0a 00 "
		
	strings :
		$a_80_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //Software\Microsoft\Windows\CurrentVersion\Run  0a 00 
		$a_80_1 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //Select * from Win32_ComputerSystem  0a 00 
		$a_80_2 = {6d 69 63 72 6f 73 6f 66 74 20 63 6f 72 70 6f 72 61 74 69 6f 6e } //microsoft corporation  0a 00 
		$a_81_3 = {56 49 52 54 55 41 4c } //0a 00 
		$a_80_4 = {76 6d 77 61 72 65 } //vmware  0a 00 
		$a_80_5 = {56 69 72 74 75 61 6c 42 6f 78 } //VirtualBox  01 00 
		$a_80_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  01 00 
		$a_80_7 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //CheckRemoteDebuggerPresent  01 00 
		$a_80_8 = {43 72 65 61 74 65 46 69 6c 65 4d 61 70 70 69 6e 67 } //CreateFileMapping  01 00 
		$a_80_9 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //UnmapViewOfFile  01 00 
		$a_80_10 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //MapViewOfFile  01 00 
		$a_80_11 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //NtQueryInformationProcess  00 00 
	condition:
		any of ($a_*)
 
}