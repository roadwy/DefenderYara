
rule SoftwareBundler_Win32_ICLoader{
	meta:
		description = "SoftwareBundler:Win32/ICLoader,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 81 39 4d 5a 0f 85 90 01 02 00 00 8b 41 3c 68 00 01 00 00 03 c1 50 a3 90 01 04 ff d6 85 c0 0f 85 90 01 02 00 00 a1 90 01 04 66 81 38 50 45 90 00 } //1
		$a_01_1 = {75 0b 33 1a ff d3 cc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule SoftwareBundler_Win32_ICLoader_2{
	meta:
		description = "SoftwareBundler:Win32/ICLoader,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 8a 45 0f d3 e3 33 db 0b 1d 90 01 04 03 d9 8a 0b 90 90 90 90 33 c1 88 03 90 90 42 81 fa 27 07 00 00 89 55 08 7e 90 00 } //1
		$a_00_1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 69 00 74 00 63 00 68 00 65 00 6e 00 00 00 } //1
		$a_00_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 61 00 76 00 61 00 74 00 61 00 72 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}