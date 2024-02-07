
rule Trojan_Win32_Loasum_A{
	meta:
		description = "Trojan:Win32/Loasum.A,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {03 45 fc 03 c8 0f b6 c9 89 4d fc 8a 04 31 88 04 37 47 88 1c 31 81 ff 00 01 00 00 } //0a 00 
		$a_01_1 = {0f b6 04 08 8b 4d 08 32 04 19 88 03 43 83 6d 10 01 8b 45 fc 89 5d 0c 75 } //01 00 
		$a_03_2 = {6a 64 6a 00 ff 90 02 05 83 ee 01 75 90 00 } //01 00 
		$a_01_3 = {55 4e 4b 4e 4f 57 4e 44 4c 4c 2e 44 4c 4c 00 55 6e 69 6d 70 6c 65 6d 65 6e 74 65 64 41 50 49 } //01 00 
		$a_01_4 = {6e 65 74 77 6f 72 6b 65 78 70 6c 6f 72 65 72 2e 44 4c 4c } //01 00  networkexplorer.DLL
		$a_01_5 = {4e 6c 73 44 61 74 61 30 30 30 30 2e 44 4c 4c } //01 00  NlsData0000.DLL
		$a_01_6 = {4e 65 74 50 72 6f 6a 57 2e 44 4c 4c } //01 00  NetProjW.DLL
		$a_01_7 = {47 68 6f 66 72 2e 44 4c 4c } //01 00  Ghofr.DLL
		$a_01_8 = {66 67 31 32 32 2e 44 4c 4c } //00 00  fg122.DLL
		$a_00_9 = {5d 04 00 00 96 1a 05 80 5c 3b 00 } //00 97 
	condition:
		any of ($a_*)
 
}