
rule Trojan_Win32_Sirefef_S{
	meta:
		description = "Trojan:Win32/Sirefef.S,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 70 2f 74 61 73 6b 32 2e 70 68 70 3f 77 3d 25 75 26 69 3d 25 53 26 6e 3d 25 75 } //1 GET /p/task2.php?w=%u&i=%S&n=%u
		$a_01_1 = {25 00 77 00 5a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 25 00 30 00 38 00 78 00 } //1 %wZ\Software\%08x
		$a_00_2 = {3d 05 00 00 80 74 cf 33 ff 3b c7 0f 8c a7 00 00 00 33 db 43 39 5e 04 0f 85 9b 00 00 00 8b 46 08 83 f8 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Sirefef_S_2{
	meta:
		description = "Trojan:Win32/Sirefef.S,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 70 2f 74 61 73 6b 32 2e 70 68 70 3f 77 3d 25 75 26 69 3d 25 53 26 6e 3d 25 75 } //1 GET /p/task2.php?w=%u&i=%S&n=%u
		$a_01_1 = {25 00 77 00 5a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 25 00 30 00 38 00 78 00 } //1 %wZ\Software\%08x
		$a_00_2 = {3d 05 00 00 80 74 cf 33 ff 3b c7 0f 8c a7 00 00 00 33 db 43 39 5e 04 0f 85 9b 00 00 00 8b 46 08 83 f8 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}