
rule Trojan_Win32_Sirefef_AF{
	meta:
		description = "Trojan:Win32/Sirefef.AF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {5c 00 3f 00 3f 00 5c 00 41 00 43 00 50 00 49 00 23 00 50 00 4e 00 50 00 30 00 33 00 30 00 33 00 23 00 32 00 26 00 64 00 61 00 31 00 61 00 33 00 66 00 66 00 26 00 30 00 5c 00 55 00 5c 00 ?? 00 25 00 30 00 38 00 78 00 } //1
		$a_01_1 = {0f b7 71 0e 0f b7 41 0c 83 65 f8 00 8d 44 c1 10 85 f6 74 49 8b ce c1 e1 03 2b ca 03 c8 3b 4d fc 73 3b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Sirefef_AF_2{
	meta:
		description = "Trojan:Win32/Sirefef.AF,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {5c 00 3f 00 3f 00 5c 00 41 00 43 00 50 00 49 00 23 00 50 00 4e 00 50 00 30 00 33 00 30 00 33 00 23 00 32 00 26 00 64 00 61 00 31 00 61 00 33 00 66 00 66 00 26 00 30 00 5c 00 55 00 5c 00 ?? 00 25 00 30 00 38 00 78 00 } //1
		$a_01_1 = {0f b7 71 0e 0f b7 41 0c 83 65 f8 00 8d 44 c1 10 85 f6 74 49 8b ce c1 e1 03 2b ca 03 c8 3b 4d fc 73 3b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}