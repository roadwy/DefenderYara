
rule Trojan_PowerShell_Casur_CS_eml{
	meta:
		description = "Trojan:PowerShell/Casur.CS!eml,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6f 62 6a 57 4d 49 53 65 72 76 69 63 65 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29 } //1 objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
		$a_00_1 = {6f 62 6a 53 74 61 72 74 75 70 20 3d 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //1 objStartup = objWMIService.Get("Win32_ProcessStartup")
		$a_00_2 = {6f 62 6a 43 6f 6e 66 69 67 20 3d 20 6f 62 6a 53 74 61 72 74 75 70 2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f } //1 objConfig = objStartup.SpawnInstance_
		$a_00_3 = {6f 62 6a 43 6f 6e 66 69 67 2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 48 49 44 44 45 4e 5f 57 49 4e 44 4f 57 } //1 objConfig.ShowWindow = HIDDEN_WINDOW
		$a_00_4 = {6f 62 6a 50 72 6f 63 65 73 73 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 63 69 6d 76 32 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 22 29 } //1 objProcess = GetObject("winmgmts:\\" & strComputer & "\root\cimv2:Win32_Process")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}