
rule Worm_Win32_Autorun_DW{
	meta:
		description = "Worm:Win32/Autorun.DW,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 25 ?? ?? ?? ?? 00 68 ?? ?? ?? ?? 6a 04 6a 00 6a 04 6a 00 6a ff e8 ea 01 00 00 85 c0 74 ?? a3 ?? ?? ?? ?? 6a 04 6a 00 6a 00 6a 02 ff 35 ac 22 00 10 e8 f2 01 00 00 85 c0 74 ?? ff 75 08 8f 00 50 e8 fb 01 00 00 6a 00 ff 35 cc 22 00 10 68 5f 13 00 10 6a 05 e8 05 02 00 00 } //1
		$a_00_1 = {6e 74 68 69 64 65 2e 64 6c 6c } //1 nthide.dll
		$a_00_2 = {48 69 64 65 50 72 6f 63 65 73 } //1 HideProces
		$a_00_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_4 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NtQuerySystemInformation
		$a_00_5 = {45 6e 75 6d 57 69 6e 64 6f 77 73 } //1 EnumWindows
		$a_00_6 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 } //1 Process32First
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}