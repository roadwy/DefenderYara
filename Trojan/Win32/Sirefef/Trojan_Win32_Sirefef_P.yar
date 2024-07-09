
rule Trojan_Win32_Sirefef_P{
	meta:
		description = "Trojan:Win32/Sirefef.P,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 64 69 73 63 0f 84 ?? ?? ?? ?? 3d 73 65 6e 64 } //10
		$a_01_1 = {8b 4b 54 f3 a4 0f b7 43 14 0f b7 53 06 8d 44 18 18 83 c0 0c 8b 08 8b 75 08 8b 7d 90 01 01 03 f1 03 f9 8b 48 90 01 01 83 c0 28 4a f3 a4 75 e9 } //10
		$a_03_2 = {53 68 73 65 6e 64 8b c7 8b ce e8 ?? ?? ?? ?? 8b d8 85 db 75 0d ff 76 ?? e8 ?? ?? ?? ?? 6a 08 58 } //10
		$a_03_3 = {c6 06 e8 6a 07 56 c6 46 05 eb c6 46 06 ?? ff d7 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*1) >=1
 
}
rule Trojan_Win32_Sirefef_P_2{
	meta:
		description = "Trojan:Win32/Sirefef.P,SIGNATURE_TYPE_ARHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 64 69 73 63 0f 84 ?? ?? ?? ?? 3d 73 65 6e 64 } //10
		$a_01_1 = {8b 4b 54 f3 a4 0f b7 43 14 0f b7 53 06 8d 44 18 18 83 c0 0c 8b 08 8b 75 08 8b 7d fc 03 f1 03 f9 8b 48 fc 83 c0 28 4a f3 a4 75 e9 } //10
		$a_03_2 = {53 68 73 65 6e 64 8b c7 8b ce e8 ?? ?? ?? ?? 8b d8 85 db 75 0d ff 76 ?? e8 ?? ?? ?? ?? 6a 08 58 } //10
		$a_03_3 = {c6 06 e8 6a 07 56 c6 46 05 eb c6 46 06 ?? ff d7 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*1) >=20
 
}