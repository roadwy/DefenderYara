
rule TrojanDownloader_Win32_Perkesh_E{
	meta:
		description = "TrojanDownloader:Win32/Perkesh.E,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0b 00 00 05 00 "
		
	strings :
		$a_03_0 = {51 56 56 6a 0b ff d0 3b c6 0f 84 90 01 04 3d 04 00 00 c0 90 00 } //05 00 
		$a_03_1 = {6a 00 6a 40 ff 15 90 01 04 85 c0 89 45 fc 74 1f 6a 01 6a 00 8d 4d fc 68 ff 0f 1f 00 51 6a ff 50 6a ff ff d7 6a 00 ff 75 fc ff 15 90 00 } //05 00 
		$a_01_2 = {50 73 53 65 74 4c 6f 61 64 49 6d 61 67 65 4e 6f 74 69 66 79 52 6f 75 74 69 6e 65 } //05 00  PsSetLoadImageNotifyRoutine
		$a_01_3 = {5a 77 53 79 73 74 65 6d 44 65 62 75 67 43 6f 6e 74 72 6f 6c } //05 00  ZwSystemDebugControl
		$a_01_4 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //05 00  ZwQuerySystemInformation
		$a_01_5 = {5a 77 44 75 70 6c 69 63 61 74 65 4f 62 6a 65 63 74 } //02 00  ZwDuplicateObject
		$a_01_6 = {55 68 1c 00 22 00 57 ff 15 } //02 00 
		$a_01_7 = {68 a0 bb 0d 00 ff 15 } //02 00 
		$a_01_8 = {68 20 bf 02 00 ff 15 } //01 00 
		$a_01_9 = {4b 41 56 33 32 2e 65 78 65 } //01 00  KAV32.exe
		$a_01_10 = {33 36 30 53 61 66 65 2e 65 78 65 } //00 00  360Safe.exe
	condition:
		any of ($a_*)
 
}