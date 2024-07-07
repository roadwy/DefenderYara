
rule Trojan_AndroidOS_Donot_B{
	meta:
		description = "Trojan:AndroidOS/Donot.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_00_0 = {66 49 4f 65 54 4e 4d 76 69 62 5a 32 39 4f 74 6f 6c 63 33 35 73 51 3d 3d } //1 fIOeTNMvibZ29Otolc35sQ==
		$a_00_1 = {6e 58 52 61 61 4a 78 63 4b 2f 44 49 32 69 4c 4c 51 43 65 6f 47 67 3d 3d } //1 nXRaaJxcK/DI2iLLQCeoGg==
		$a_00_2 = {2e 61 6d 72 3a 3a 41 64 64 65 64 } //1 .amr::Added
		$a_00_3 = {79 67 39 61 56 7a 64 58 56 62 75 74 36 75 63 59 36 4d 55 4a 79 67 3d 3d } //1 yg9aVzdXVbut6ucY6MUJyg==
		$a_00_4 = {6a 42 78 50 69 41 53 6d 6c 4c 73 70 62 37 59 6c 79 69 5a 59 77 41 3d 3d } //1 jBxPiASmlLspb7YlyiZYwA==
		$a_00_5 = {33 66 70 6c 57 76 49 35 41 32 41 37 64 64 2b 63 57 50 70 55 76 51 3d 3d } //1 3fplWvI5A2A7dd+cWPpUvQ==
		$a_00_6 = {70 62 72 35 67 62 62 7a 2b 32 34 61 69 4a 70 71 58 49 2b 4c 35 51 3d 3d } //1 pbr5gbbz+24aiJpqXI+L5Q==
		$a_00_7 = {72 48 4d 57 6a 32 49 57 71 31 77 30 6e 42 64 51 38 4e 6f 70 70 41 3d 3d } //1 rHMWj2IWq1w0nBdQ8NoppA==
		$a_00_8 = {6f 63 63 75 53 74 79 41 67 7a 4a 39 71 6b 48 78 56 35 64 6a 47 67 3d 3d } //1 occuStyAgzJ9qkHxV5djGg==
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=6
 
}