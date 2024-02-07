
rule TrojanDownloader_O97M_Obfuse_PRDE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PRDE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 5f 44 61 74 61 20 22 35 61 66 32 65 62 38 35 38 66 34 35 36 66 32 64 35 61 37 32 33 62 31 34 65 34 33 63 31 31 37 34 22 } //01 00  Get_Data "5af2eb858f456f2d5a723b14e43c1174"
		$a_01_1 = {6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 45 78 65 63 51 75 65 72 79 28 22 53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d 22 2c 20 2c 20 34 38 29 } //01 00  objWMIService.ExecQuery("Select * from Win32_ComputerSystem", , 48)
		$a_01_2 = {6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 45 78 65 63 51 75 65 72 79 28 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 6f 72 22 2c 20 22 57 51 4c 22 2c 20 5f } //01 00  objWMIService.ExecQuery("SELECT * FROM Win32_Processor", "WQL", _
		$a_01_3 = {28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 64 6f 74 53 70 6c 61 63 65 20 26 20 22 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29 } //01 00  ("winmgmts:\\" & dotSplace & "\root\cimv2")
		$a_01_4 = {22 54 61 72 67 65 74 65 64 45 6d 70 6c 6f 79 65 65 73 31 38 30 38 32 31 2e 78 6c 73 6d 22 20 54 68 65 6e } //01 00  "TargetedEmployees180821.xlsm" Then
		$a_01_5 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  CreateObject("WScript.Shell")
		$a_01_6 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 4e 65 74 77 6f 72 6b 22 29 } //01 00  = CreateObject("WScript.Network")
		$a_01_7 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 44 65 74 61 69 6c 73 2e 64 61 74 22 } //01 00  = Environ("Temp") & "\Details.dat"
		$a_01_8 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 54 45 44 65 74 61 69 6c 73 2e 64 61 74 22 } //01 00  = Environ("Temp") & "\TEDetails.dat"
		$a_01_9 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 49 6e 63 44 65 74 61 69 6c 73 2e 6c 6f 67 22 } //00 00  = Environ("Temp") & "\IncDetails.log"
	condition:
		any of ($a_*)
 
}