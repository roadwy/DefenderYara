
rule VirTool_BAT_Injantivm_GG_MTB{
	meta:
		description = "VirTool:BAT/Injantivm.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 56 4d 77 61 72 65 } //SOFTWARE\VMware  1
		$a_80_2 = {73 61 6e 64 62 6f 78 69 65 72 70 63 73 73 } //sandboxierpcss  1
		$a_80_3 = {70 63 61 6c 75 61 2e 65 78 65 } //pcalua.exe  1
		$a_80_4 = {49 6e 73 74 61 6c 6c 55 74 69 6c 2e 65 78 65 } //InstallUtil.exe  1
		$a_80_5 = {52 65 67 41 73 6d 2e 65 78 65 } //RegAsm.exe  1
		$a_80_6 = {41 64 64 49 6e 50 72 6f 63 65 73 73 33 32 2e 65 78 65 } //AddInProcess32.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}