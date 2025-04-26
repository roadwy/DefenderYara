
rule Trojan_Win32_Farfli_MAN_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {6a 01 8d 95 f8 fe ff ff 90 0a 12 00 6a 00 6a 00 6a 03 6a 00 [0-09] 68 00 00 00 80 52 ff 15 ?? ?? ?? ?? 8b f0 83 fe ff 75 } //1
		$a_01_1 = {47 65 74 44 72 69 76 65 54 79 70 65 41 } //1 GetDriveTypeA
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_4 = {73 6f 66 74 77 61 72 65 5c 6d 49 43 52 4f 53 4f 46 54 5c 77 49 4e 44 4f 57 53 20 6e 74 5c 63 55 52 52 45 4e 54 76 45 52 53 49 4f 4e 5c 73 56 43 48 4f 53 54 } //1 software\mICROSOFT\wINDOWS nt\cURRENTvERSION\sVCHOST
		$a_01_5 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 41 } //1 MapVirtualKeyA
		$a_01_6 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}