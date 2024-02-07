
rule Backdoor_WinNT_Frurat_A{
	meta:
		description = "Backdoor:WinNT/Frurat.A,SIGNATURE_TYPE_JAVAHSTR_EXT,11 00 11 00 07 00 00 05 00 "
		
	strings :
		$a_03_0 = {63 6f 6e 65 78 69 6f 6e 90 02 10 6a 61 76 61 2f 6e 65 74 2f 53 6f 63 6b 65 74 90 00 } //05 00 
		$a_03_1 = {6f 70 63 69 6f 6e 65 73 2f 4f 70 63 69 6f 6e 90 02 10 66 69 6c 65 90 00 } //05 00 
		$a_03_2 = {70 75 65 72 74 6f 90 02 10 70 75 65 72 74 6f 90 02 10 70 61 73 73 90 02 10 74 69 6d 65 90 00 } //01 00 
		$a_01_3 = {75 72 6c 64 6f 77 6e 6c 6f 61 64 } //01 00  urldownload
		$a_01_4 = {67 65 74 50 61 73 73 77 6f 72 64 } //01 00  getPassword
		$a_01_5 = {56 61 6c 6f 72 20 64 65 20 63 6f 6d 61 6e 64 6f 3a } //01 00  Valor de comando:
		$a_03_6 = {70 6c 75 67 69 6e 4c 6f 63 61 6c 90 02 10 75 72 6c 90 02 10 75 72 6c 90 00 } //00 00 
		$a_00_7 = {bf ec 00 00 12 00 12 00 0a 00 00 02 } //00 13 
	condition:
		any of ($a_*)
 
}
rule Backdoor_WinNT_Frurat_A_2{
	meta:
		description = "Backdoor:WinNT/Frurat.A,SIGNATURE_TYPE_JAVAHSTR_EXT,12 00 12 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 65 74 52 65 73 6f 75 72 63 65 41 73 53 74 72 65 61 6d } //02 00  getResourceAsStream
		$a_01_1 = {67 65 74 53 79 73 74 65 6d 4c 6f 6f 6b 41 6e 64 46 65 65 6c 43 6c 61 73 73 4e 61 6d 65 } //02 00  getSystemLookAndFeelClassName
		$a_03_2 = {70 61 73 73 90 02 10 70 6f 72 74 90 02 10 70 6f 72 74 90 00 } //01 00 
		$a_01_3 = {66 72 61 75 74 61 73 } //01 00  frautas
		$a_01_4 = {63 6f 6e 66 69 67 2e } //01 00  config.
		$a_01_5 = {57 69 6e 64 6f 77 73 53 74 61 72 74 75 70 53 65 72 76 69 63 65 } //01 00  WindowsStartupService
		$a_01_6 = {61 64 64 53 68 75 74 64 6f 77 6e 48 6f 6f 6b } //0a 00  addShutdownHook
		$a_03_7 = {74 6d 70 64 69 72 90 02 10 66 72 61 75 74 61 73 2e 6c 6f 63 6b 90 00 } //0a 00 
		$a_01_8 = {66 72 75 74 61 73 72 61 74 2e } //0a 00  frutasrat.
		$a_03_9 = {68 6f 73 74 90 02 10 70 61 73 73 90 02 10 70 6f 72 74 90 02 10 70 6f 72 74 90 02 10 74 65 6d 70 90 00 } //00 00 
		$a_00_10 = {bf 04 01 00 1b 00 1b 00 } //0c 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_WinNT_Frurat_A_3{
	meta:
		description = "Backdoor:WinNT/Frurat.A,SIGNATURE_TYPE_JAVAHSTR_EXT,1b 00 1b 00 0c 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 61 76 61 2f 75 74 69 6c 2f 6c 6f 67 67 69 6e 67 2f 4c 6f 67 67 65 72 } //05 00  java/util/logging/Logger
		$a_01_1 = {6a 61 76 61 2f 69 6f 2f 46 69 6c 65 } //05 00  java/io/File
		$a_01_2 = {65 78 74 72 61 2f 52 65 67 69 73 74 72 79 55 74 69 6c 73 } //05 00  extra/RegistryUtils
		$a_03_3 = {44 65 73 69 6e 73 74 61 6c 61 90 02 10 72 75 74 61 90 00 } //05 00 
		$a_03_4 = {72 75 74 61 90 02 10 4c 6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67 90 02 10 72 65 67 69 73 74 72 6f 90 00 } //01 00 
		$a_01_5 = {67 65 74 52 65 73 6f 75 72 63 65 41 73 53 74 72 65 61 6d } //01 00  getResourceAsStream
		$a_01_6 = {67 65 74 52 75 6e 74 69 6d 65 } //01 00  getRuntime
		$a_01_7 = {67 65 74 4c 6f 67 67 65 72 } //01 00  getLogger
		$a_01_8 = {73 63 68 74 61 73 6b 73 } //01 00  schtasks
		$a_01_9 = {2f 64 65 6c 65 74 65 } //01 00  /delete
		$a_01_10 = {72 65 67 69 73 74 72 6f 4b 65 79 } //01 00  registroKey
		$a_01_11 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  Windows\CurrentVersion\Run
		$a_00_12 = {5d 04 00 00 46 fc 02 80 5c 21 00 00 47 fc 02 80 00 00 01 } //00 08 
	condition:
		any of ($a_*)
 
}