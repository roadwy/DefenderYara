
rule Backdoor_WinNT_Farfli_B_sys{
	meta:
		description = "Backdoor:WinNT/Farfli.B!sys,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_02_0 = {50 ff d7 8d 45 fc 89 75 fc 50 6a 01 5b 8d 45 ec 53 56 68 00 80 00 00 50 56 ff 75 08 ff 15 ?? ?? 01 00 3b c6 0f 8c ?? 00 00 00 8d 45 e4 68 ?? ?? 01 00 50 ff d7 8d 45 ec 50 8d 45 e4 50 ff 15 ?? ?? 01 00 8b f8 3b fe 7d 10 ff 75 fc ff 15 ?? ?? 01 00 8b c7 } //1
		$a_02_1 = {89 7d e0 89 75 dc 89 75 e4 89 75 e8 ff 15 ?? ?? 01 00 8b 3d ?? ?? 01 00 85 c0 7c 40 6a 04 68 00 00 10 00 8d 45 fc 6a 01 50 56 68 00 10 00 00 56 68 ?? ?? 01 00 6a ff ff 35 ?? ?? 01 00 89 75 fc ff 15 ?? ?? 01 00 85 c0 7c 04 b0 01 eb 18 ff 35 ?? ?? 01 00 89 35 ?? ?? 01 00 ff d7 ff 35 ?? ?? 01 00 ff d7 32 c0 5f 5e 5b c9 c3 cc } //1
		$a_00_2 = {ab ab ab ab ab 8d 45 f4 56 89 45 dc 56 33 c0 8d 7d f0 6a 21 89 75 ec 6a 01 6a 01 ab 68 80 00 00 00 8d 45 ec 56 50 8d 45 d4 c7 45 d4 18 00 00 00 50 8d 45 fc 68 80 00 10 00 50 89 75 d8 c7 45 e0 40 02 00 00 89 75 e4 89 75 e8 89 75 fc ff 15 } //1
		$a_01_3 = {4b 65 44 65 6c 61 79 45 78 65 63 75 74 69 6f 6e 54 68 72 65 61 64 } //1 KeDelayExecutionThread
		$a_00_4 = {5a 77 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 ZwMapViewOfSection
		$a_01_5 = {5a 77 43 72 65 61 74 65 53 65 63 74 69 6f 6e } //1 ZwCreateSection
		$a_01_6 = {49 6f 44 65 6c 65 74 65 44 65 76 69 63 65 } //1 IoDeleteDevice
		$a_01_7 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //1 ntoskrnl.exe
		$a_01_8 = {5a 77 43 72 65 61 74 65 4b 65 79 } //1 ZwCreateKey
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}