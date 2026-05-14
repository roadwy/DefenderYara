
rule Trojan_Win32_PlugX_AB_MTB{
	meta:
		description = "Trojan:Win32/PlugX.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 80 78 ?? 00 0f 95 c0 c3 53 b8 ?? 00 00 00 8b 4c 24 0c 8b 54 24 08 66 ?? 0f b6 5c 01 ?? 31 c3 88 5c 02 ?? 40 83 f8 ?? 75 ef 5b c3 } //6
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //2 SOFTWARE\Microsoft\Windows NT\CurrentVersion
		$a_81_2 = {64 6c 63 6f 72 65 2e 64 6c 6c } //2 dlcore.dll
		$a_81_3 = {31 2c 20 39 2c 20 36 35 36 2c 20 34 30 31 } //2 1, 9, 656, 401
	condition:
		((#a_03_0  & 1)*6+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2) >=12
 
}