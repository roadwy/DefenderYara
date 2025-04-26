
rule Trojan_Win32_Emotet_GC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 14 11 8b 4d ?? 0f b6 04 01 33 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 8b 5d ?? 03 1d } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Emotet_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 8a 0c 18 8a 14 32 32 d1 8d 4c 24 ?? 51 88 13 } //1
		$a_81_1 = {41 54 6e 2a 30 5a 24 57 58 23 30 6f 76 75 4b 4d 7b 38 48 61 75 30 69 33 70 65 57 63 52 6c 33 48 77 43 30 4c 3f 2a 4e 74 53 68 7b 72 70 6b 39 53 50 64 61 30 67 77 7a 77 31 35 67 52 32 64 64 65 61 52 42 31 2a 5a 3f 4e 4a 56 78 6d 50 4b } //1 ATn*0Z$WX#0ovuKM{8Hau0i3peWcRl3HwC0L?*NtSh{rpk9SPda0gwzw15gR2ddeaRB1*Z?NJVxmPK
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_GC_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {6b c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 6e c6 44 24 ?? 65 88 44 24 ?? c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 [0-19] ff d5 } //10
		$a_02_1 = {6a 00 ff 15 [0-19] c6 [0-03] 74 c6 [0-03] 61 c6 [0-03] 73 c6 [0-03] 6b c6 [0-03] 6d c6 [0-03] 67 c6 [0-03] 72 c6 [0-03] 2e c6 [0-03] 65 c6 [0-03] 78 c6 [0-03] 65 [0-06] ff } //3
		$a_02_2 = {8b f8 53 8d [0-0c] c6 [0-03] 74 c6 [0-03] 61 c6 [0-03] 73 c6 [0-03] 6b c6 [0-03] 6d c6 [0-03] 67 c6 [0-03] 72 c6 [0-03] 2e c6 [0-03] 65 c6 [0-03] 78 c6 [0-03] 65 88 [0-03] ff } //3
		$a_80_3 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  1
		$a_80_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*3+(#a_02_2  & 1)*3+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=14
 
}