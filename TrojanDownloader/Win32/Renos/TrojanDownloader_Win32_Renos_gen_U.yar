
rule TrojanDownloader_Win32_Renos_gen_U{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!U,SIGNATURE_TYPE_PEHSTR_EXT,50 00 46 00 0d 00 00 "
		
	strings :
		$a_00_0 = {56 69 72 75 73 20 41 74 74 61 63 6b 21 21 21 20 54 68 65 20 79 6f 75 72 20 73 79 73 74 65 6d 20 6f 6e 20 63 6f 6d 70 75 74 65 72 20 69 73 20 64 61 6d 61 67 65 64 2e } //50 Virus Attack!!! The your system on computer is damaged.
		$a_02_1 = {75 8b ec 81 c4 00 fe ff ff 71 76 77 68 ff 00 00 00 8d ?? 01 ff ff ff ?? e8 ?? ?? ?? ?? 8d 85 02 fe ff ff 70 6a 00 68 ?? ?? ?? ?? 8d 85 01 ff ff ff 70 e8 ?? ?? ?? ?? 8d 85 02 fe ff ff 70 e8 ?? ?? ?? ?? 8d 85 02 fe ff ff 70 ff 15 ?? ?? ?? ?? 83 c4 04 b9 03 00 00 00 2b c1 8d bd 02 fe ff ff } //5
		$a_02_2 = {8b ec 83 c4 f8 6a 01 6a 00 ff 75 08 8d 05 [0-04] 70 8d 05 [0-04] 70 6a 00 ff 15 [0-04] b8 01 00 00 00 c9 } //5
		$a_02_3 = {75 8b ec 81 c4 18 fe ff ff [0-03] e8 ?? ?? ?? ?? 83 f8 00 0f 85 ?? 00 00 00 } //5
		$a_00_4 = {6a 06 6a 00 6a 00 6a 00 6a 00 6a ff ff 75 08 e8 } //5
		$a_02_5 = {75 1e 6a 64 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 01 00 00 00 eb 1c 6a 66 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 68 ?? ?? ?? ?? 6a 01 e8 ?? ?? ?? ?? c9 c2 10 00 } //5
		$a_01_6 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e 41 } //1 Shell_NotifyIconA
		$a_01_7 = {61 6c 6c 65 72 74 00 } //1
		$a_00_8 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_00_9 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 75 6e 69 6e 73 74 61 6c 6c } //1 software\microsoft\windows\currentversion\uninstall
		$a_00_10 = {73 68 65 6c 6c 65 78 65 63 75 74 65 61 } //1 shellexecutea
		$a_00_11 = {71 76 6c 5d 6a 76 5d 6c 6a 5d 79 5c 7e 71 74 5d } //1 qvl]jv]lj]y\~qt]
		$a_01_12 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_00_0  & 1)*50+(#a_02_1  & 1)*5+(#a_02_2  & 1)*5+(#a_02_3  & 1)*5+(#a_00_4  & 1)*5+(#a_02_5  & 1)*5+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_01_12  & 1)*1) >=70
 
}