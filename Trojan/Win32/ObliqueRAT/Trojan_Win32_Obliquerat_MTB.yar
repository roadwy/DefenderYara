
rule Trojan_Win32_Obliquerat_MTB{
	meta:
		description = "Trojan:Win32/Obliquerat!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 5f 53 61 6c 61 6e 5f 6e 61 6d 65 20 3d 20 22 73 67 72 6d 62 72 6f 6b 72 22 } //1 file_Salan_name = "sgrmbrokr"
		$a_01_1 = {7a 69 70 5f 53 61 6c 61 6e 5f 66 69 6c 65 20 3d 20 66 6c 64 72 5f 53 61 6c 61 6e 5f 6e 61 6d 65 20 26 20 66 69 6c 65 5f 53 61 6c 61 6e 5f 6e 61 6d 65 20 26 20 22 2e 64 6f 63 22 } //1 zip_Salan_file = fldr_Salan_name & file_Salan_name & ".doc"
		$a_03_2 = {4e 61 6d 65 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-09] 2e 64 6f 63 22 20 41 73 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-09] 2e 65 78 65 22 } //1
		$a_03_3 = {45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c [0-06] 2e 75 72 6c 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}