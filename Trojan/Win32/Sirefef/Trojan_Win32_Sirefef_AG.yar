
rule Trojan_Win32_Sirefef_AG{
	meta:
		description = "Trojan:Win32/Sirefef.AG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 47 4e 4f 4c 31 06 d1 c0 83 c6 04 49 75 f6 } //2
		$a_03_1 = {8b 46 18 6a 4d 83 c0 0c 68 ?? ?? ?? ?? 50 e8 } //1
		$a_03_2 = {8b 46 10 6a 46 83 c0 0c 68 ?? ?? ?? ?? 50 e8 } //1
		$a_01_3 = {8b 4b 54 57 8b fd f3 a4 0f b7 43 14 0f b7 53 06 8d 44 18 18 83 c0 0c 8b 08 } //2
		$a_00_4 = {c7 43 08 30 30 31 00 c6 43 05 03 c7 43 54 30 30 32 00 c6 43 51 03 ff 15 } //2
		$a_00_5 = {25 00 77 00 5a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 25 00 30 00 38 00 78 00 } //2 %wZ\Software\%08x
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=3
 
}
rule Trojan_Win32_Sirefef_AG_2{
	meta:
		description = "Trojan:Win32/Sirefef.AG,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 47 4e 4f 4c 31 06 d1 c0 83 c6 04 49 75 f6 } //2
		$a_03_1 = {8b 46 18 6a 4d 83 c0 0c 68 ?? ?? ?? ?? 50 e8 } //1
		$a_03_2 = {8b 46 10 6a 46 83 c0 0c 68 ?? ?? ?? ?? 50 e8 } //1
		$a_01_3 = {8b 4b 54 57 8b fd f3 a4 0f b7 43 14 0f b7 53 06 8d 44 18 18 83 c0 0c 8b 08 } //2
		$a_00_4 = {c7 43 08 30 30 31 00 c6 43 05 03 c7 43 54 30 30 32 00 c6 43 51 03 ff 15 } //2
		$a_00_5 = {25 00 77 00 5a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 25 00 30 00 38 00 78 00 } //2 %wZ\Software\%08x
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=3
 
}