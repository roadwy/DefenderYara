
rule Backdoor_Win32_Plugx_C{
	meta:
		description = "Backdoor:Win32/Plugx.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 00 00 00 00 78 62 69 6e 30 31 00 } //1
		$a_03_1 = {53 33 c0 b1 ?? 8a 98 ?? ?? ?? 00 32 d9 88 98 ?? ?? ?? 00 40 3d ?? ?? 00 00 72 ea } //1
		$a_03_2 = {6a 40 68 00 10 00 00 68 ?? ?? 00 00 6a 00 ff d3 8b f0 56 68 ?? ?? 00 00 68 ?? ?? 40 00 e8 67 fa ff ff 8b f8 6a 40 68 00 10 00 00 57 6a 00 ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
rule Backdoor_Win32_PlugX_C{
	meta:
		description = "Backdoor:Win32/PlugX.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 12 68 28 20 00 10 8d 85 fc f7 ff ff 50 ff 15 08 20 00 10 53 56 57 6a 40 } //1
		$a_01_1 = {6b c0 64 03 c1 3d 2e 2b 33 01 0f 82 99 00 00 00 56 6a 00 } //1
		$a_01_2 = {0f b6 c0 33 c1 a3 08 30 00 10 c6 06 e9 81 35 08 30 00 10 e9 00 00 00 5e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}