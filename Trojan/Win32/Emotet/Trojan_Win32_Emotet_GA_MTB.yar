
rule Trojan_Win32_Emotet_GA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c0 04 0f af 05 ?? ?? ?? ?? 03 d0 8d 47 01 0f af c7 2b d0 8b 44 24 ?? 2b d3 2b d1 8a 0c 32 30 08 8b 44 24 ?? 40 89 44 24 ?? 3b 44 24 ?? 0f 82 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Emotet_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b c8 c6 01 00 8d 49 01 83 ee 01 75 } //1
		$a_02_1 = {03 c1 83 e0 ?? 0f b6 44 05 ?? 32 42 ?? 88 41 ?? 8b 45 ?? 03 c1 83 e0 ?? 0f b6 44 05 ?? 32 42 ?? 88 41 ?? 8d 04 17 83 c1 04 3d 00 32 02 00 72 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {5c 7b 61 61 35 62 36 61 38 30 2d 62 38 33 34 2d 31 31 64 30 2d 39 33 32 66 2d 30 30 61 30 63 39 30 64 63 61 61 39 7d } //\{aa5b6a80-b834-11d0-932f-00a0c90dcaa9}  1
		$a_02_1 = {8b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5d c3 90 0a 60 00 b8 ?? ?? ?? ?? b8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 31 } //1
		$a_02_2 = {83 c0 01 89 45 f8 eb 90 0a 40 00 74 ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 [0-03] 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 8b 75 ?? 8a ?? ?? 88 ?? ?? 8b 45 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_GA_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 06 8b 4d [0-02] 5f 5e 64 [0-02] 00 00 00 00 5b c9 c2 } //1
		$a_02_1 = {6a ff 50 64 [0-02] 00 00 00 00 50 8b 44 [0-02] 64 [0-02] 00 00 00 00 89 6c [0-02] 8d 6c [0-02] 50 c3 } //1
		$a_00_2 = {66 8b 06 66 f7 d8 1b c0 23 c6 5e 5f 5b c3 } //1
		$a_02_3 = {50 89 7c 24 [0-02] c6 [0-03] 74 c6 [0-03] 61 c6 [0-03] 73 c6 [0-03] 6b c6 [0-03] 6d c6 [0-03] 67 c6 [0-03] 72 c6 [0-03] 2e c6 [0-03] 65 c6 [0-03] 78 c6 [0-03] 65 88 5c [0-02] ff d5 } //1
		$a_80_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}