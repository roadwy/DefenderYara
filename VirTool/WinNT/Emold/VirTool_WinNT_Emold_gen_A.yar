
rule VirTool_WinNT_Emold_gen_A{
	meta:
		description = "VirTool:WinNT/Emold.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //0a 00  NtWriteVirtualMemory
		$a_00_1 = {4e 74 50 72 6f 74 65 63 74 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //0a 00  NtProtectVirtualMemory
		$a_00_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //0a 00  KeServiceDescriptorTable
		$a_00_3 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6e 00 74 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 } //01 00  \SystemRoot\system32\ntdll.dll
		$a_02_4 = {8b 45 fc 0f b7 08 8b c1 66 25 00 f0 66 3d 00 30 75 90 01 01 81 e1 ff 0f 00 00 03 0e 8b 04 19 03 c2 90 00 } //01 00 
		$a_02_5 = {fa 0f 20 c0 8b c0 89 45 90 01 01 8b db 25 ff ff fe ff 0f 22 c0 8b 45 90 01 01 8b 55 90 01 01 8b db f0 90 00 } //01 00 
		$a_02_6 = {25 ff ff fe ff 0f 22 c0 8b 45 90 01 01 8b 55 90 01 03 f0 87 10 90 01 02 8b 45 90 01 01 0f 22 c0 fb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}