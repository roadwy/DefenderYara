
rule Trojan_Win64_XWorm_GXF_MTB{
	meta:
		description = "Trojan:Win64/XWorm.GXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 8d 55 b0 48 8b 85 d0 00 00 00 48 c7 44 24 20 00 00 00 00 41 b9 00 00 00 00 49 89 d0 48 89 c2 b9 00 00 00 00 e8 } //5
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 63 20 63 6f 6e 66 69 67 20 57 69 6e 44 65 66 65 6e 64 20 73 74 61 72 74 3d 64 69 73 61 62 6c 65 64 20 3e 20 6e 75 6c 20 32 3e 26 31 } //1 cmd.exe /c sc config WinDefend start=disabled > nul 2>&1
		$a_01_2 = {73 63 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 20 3e 20 6e 75 6c 20 32 3e 26 31 } //1 sc stop WinDefend > nul 2>&1
		$a_80_3 = {54 45 4d 50 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //TEMP\svchost.exe  1
		$a_01_4 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 DisableRealtimeMonitoring
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}