
rule TrojanDownloader_Win32_Renos_gen_U{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!U,SIGNATURE_TYPE_PEHSTR_EXT,50 00 46 00 0d 00 00 32 00 "
		
	strings :
		$a_00_0 = {56 69 72 75 73 20 41 74 74 61 63 6b 21 21 21 20 54 68 65 20 79 6f 75 72 20 73 79 73 74 65 6d 20 6f 6e 20 63 6f 6d 70 75 74 65 72 20 69 73 20 64 61 6d 61 67 65 64 2e } //05 00  Virus Attack!!! The your system on computer is damaged.
		$a_02_1 = {75 8b ec 81 c4 00 fe ff ff 71 76 77 68 ff 00 00 00 8d 90 01 01 01 ff ff ff 90 01 01 e8 90 01 04 8d 85 02 fe ff ff 70 6a 00 68 90 01 04 8d 85 01 ff ff ff 70 e8 90 01 04 8d 85 02 fe ff ff 70 e8 90 01 04 8d 85 02 fe ff ff 70 ff 15 90 01 04 83 c4 04 b9 03 00 00 00 2b c1 8d bd 02 fe ff ff 90 00 } //05 00 
		$a_02_2 = {8b ec 83 c4 f8 6a 01 6a 00 ff 75 08 8d 05 90 02 04 70 8d 05 90 02 04 70 6a 00 ff 15 90 02 04 b8 01 00 00 00 c9 90 00 } //05 00 
		$a_02_3 = {75 8b ec 81 c4 18 fe ff ff 90 02 03 e8 90 01 04 83 f8 00 0f 85 90 01 01 00 00 00 90 00 } //05 00 
		$a_00_4 = {6a 06 6a 00 6a 00 6a 00 6a 00 6a ff ff 75 08 e8 } //05 00 
		$a_02_5 = {75 1e 6a 64 ff 35 90 01 04 e8 90 01 04 a3 90 01 04 c7 05 90 01 04 01 00 00 00 eb 1c 6a 66 ff 35 90 01 04 e8 90 01 04 a3 90 01 04 c7 05 90 01 04 00 00 00 00 68 90 01 04 6a 01 e8 90 01 04 c9 c2 10 00 90 00 } //01 00 
		$a_01_6 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //01 00  Shell_NotifyIconA
		$a_01_7 = {61 6c 6c 65 72 74 00 } //01 00 
		$a_00_8 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  explorer.exe
		$a_00_9 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 75 6e 69 6e 73 74 61 6c 6c } //01 00  software\microsoft\windows\currentversion\uninstall
		$a_00_10 = {73 68 65 6c 6c 65 78 65 63 75 74 65 61 } //01 00  shellexecutea
		$a_00_11 = {71 76 6c 5d 6a 76 5d 6c 6a 5d 79 5c 7e 71 74 5d } //01 00  qvl]jv]lj]y\~qt]
		$a_01_12 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //00 00  InternetOpenUrlA
	condition:
		any of ($a_*)
 
}