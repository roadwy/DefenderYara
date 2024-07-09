
rule Trojan_Win32_Dursg_B{
	meta:
		description = "Trojan:Win32/Dursg.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {74 4f 56 57 e8 ?? ?? 00 00 8b f8 6a 23 57 e8 ?? ?? 00 00 8b e8 8b f5 2b f7 d1 fe } //2
		$a_03_1 = {74 6d 53 55 56 57 e8 ?? ?? 00 00 8b f0 6a 23 56 e8 ?? ?? 00 00 8b e8 8b dd 2b de } //2
		$a_03_2 = {8b 04 24 83 78 0c 02 53 50 0f 94 c3 e8 ?? ?? ?? ?? 80 fb 01 5b b8 ?? ?? ?? ?? 74 05 b8 } //2
		$a_80_3 = {75 72 73 3d 00 } //urs=  1
		$a_80_4 = {6d 63 70 3d 00 } //mcp=  1
		$a_80_5 = {63 6d 70 3d 00 } //cmp=  1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}