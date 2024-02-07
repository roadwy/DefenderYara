
rule VirTool_BAT_Luxod_A{
	meta:
		description = "VirTool:BAT/Luxod.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 64 64 54 6f 53 74 61 72 74 75 70 } //01 00  AddToStartup
		$a_01_1 = {49 6e 6a 65 63 74 69 6f 6e 54 61 72 67 65 74 } //01 00  InjectionTarget
		$a_01_2 = {48 61 73 50 65 72 73 69 73 74 65 6e 63 65 } //01 00  HasPersistence
		$a_01_3 = {4d 65 6c 74 46 69 6c 65 } //01 00  MeltFile
		$a_01_4 = {45 6e 61 62 6c 65 44 6f 77 6e 6c 6f 61 64 65 72 } //01 00  EnableDownloader
		$a_01_5 = {42 79 70 61 73 73 50 72 6f 61 63 74 69 76 65 73 } //01 00  BypassProactives
		$a_01_6 = {61 00 64 00 64 00 20 00 22 00 48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 22 00 20 00 2f 00 66 00 20 00 2f 00 76 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 2c 00 22 00 } //00 00  add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /f /v shell /t REG_SZ /d explorer.exe,"
		$a_00_7 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}