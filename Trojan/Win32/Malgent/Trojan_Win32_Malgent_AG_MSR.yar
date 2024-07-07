
rule Trojan_Win32_Malgent_AG_MSR{
	meta:
		description = "Trojan:Win32/Malgent.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_80_0 = {47 65 74 55 73 65 72 4e 61 6d 65 41 } //GetUserNameA  1
		$a_80_1 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //CreateMutexA  1
		$a_80_2 = {47 6c 6f 62 61 6c 5c 67 66 78 51 4a 73 56 55 68 6b 4d 4f 53 61 64 49 6d 77 5a 46 42 62 6e 70 65 32 47 6a 76 37 48 41 } //Global\gfxQJsVUhkMOSadImwZFBbnpe2Gjv7HA  2
		$a_80_3 = {45 74 77 45 76 65 6e 74 57 72 69 74 65 } //EtwEventWrite  1
		$a_80_4 = {43 72 65 61 74 65 54 68 72 65 61 64 } //CreateThread  1
		$a_80_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //VirtualProtectEx  1
		$a_80_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //WriteProcessMemory  1
		$a_80_7 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //explorer.exe  1
		$a_80_8 = {73 76 63 68 6f 73 74 2e 65 78 65 } //svchost.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=10
 
}