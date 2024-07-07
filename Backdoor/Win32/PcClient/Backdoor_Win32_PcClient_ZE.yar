
rule Backdoor_Win32_PcClient_ZE{
	meta:
		description = "Backdoor:Win32/PcClient.ZE,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 69 63 65 4d 61 69 6e } //2 ServiceMain
		$a_01_1 = {56 8b 31 57 66 8b 7c 24 0c 66 89 3c 96 8b 31 0f b7 10 66 8b 7c 24 10 66 89 7c 96 02 66 ff 00 66 8b 00 5f 66 3d 08 00 5e 74 30 66 3d 10 00 74 2a 66 3d 20 00 74 24 66 3d 40 00 74 1e 66 3d 80 00 74 18 66 3d 00 01 74 12 66 3d 00 02 74 0c 66 3d 00 04 74 06 66 3d 00 08 75 03 } //2
		$a_01_2 = {0f b6 d0 0f b6 54 0a 0d 01 51 34 8b 51 34 3b 51 28 72 16 fe c0 3c 04 88 41 0c 73 1c 0f b6 c0 0f b6 44 08 0d d1 e8 89 41 34 8b 41 38 8b 51 14 0f af 41 34 2b d0 89 51 1c } //2
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_5 = {43 6f 6e 74 72 6f 6c 53 65 72 76 69 63 65 } //1 ControlService
		$a_01_6 = {44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c } //1 DeviceIoControl
		$a_01_7 = {49 6e 74 65 72 6e 65 74 53 65 74 4f 70 74 69 6f 6e } //1 InternetSetOption
		$a_01_8 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_9 = {53 48 44 65 6c 65 74 65 4b 65 79 } //1 SHDeleteKey
		$a_01_10 = {57 53 32 5f 33 32 2e 64 6c 6c } //1 WS2_32.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=12
 
}