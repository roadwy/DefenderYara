
rule Trojan_Win32_Veslorn_gen_B{
	meta:
		description = "Trojan:Win32/Veslorn.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8f 00 ffffff8f 00 09 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 04 66 81 38 4d 5a 75 ?? 8b 48 3c 03 c1 81 38 50 45 00 00 75 } //100
		$a_00_1 = {5c 78 63 6f 70 79 2e 65 78 65 } //10 \xcopy.exe
		$a_00_2 = {53 65 72 76 69 63 65 44 4c 4c } //10 ServiceDLL
		$a_00_3 = {2e 5c 52 45 53 53 44 54 44 4f 53 } //10 .\RESSDTDOS
		$a_00_4 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 42 46 44 44 6f 73 2e 64 6c 6c } //10 %SystemRoot%\System32\BFDDos.dll
		$a_00_5 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_00_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_7 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_8 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NtQuerySystemInformation
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=143
 
}