
rule TrojanDropper_Win32_Renos_H{
	meta:
		description = "TrojanDropper:Win32/Renos.H,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 11 00 00 "
		
	strings :
		$a_03_0 = {40 00 50 ff 15 90 09 04 00 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 [0-7a] 68 ff ff [0-30] 68 ff ff ?? ?? [0-70] 68 ff ff ?? ?? [0-30] 68 ff ff ?? ?? [0-07] e8 ?? ?? ff ff [0-50] (40 00 c3|40 00 5b c3) 90 05 10 02 90 90 81 ec 90 03 01 01 04 08 04 00 00 } //10
		$a_01_1 = {56 56 6a 25 56 } //2 VVj%V
		$a_03_2 = {83 7d f0 04 75 90 09 02 00 74 } //2
		$a_03_3 = {40 00 00 66 90 09 05 00 66 83 3d } //2
		$a_03_4 = {40 00 68 ff ff ?? ?? 68 ff ff } //2
		$a_03_5 = {fb ff ff c1 ?? 02 90 09 03 00 8d ?? c8 } //2
		$a_01_6 = {00 62 69 6e 00 } //1
		$a_01_7 = {68 82 00 00 00 } //1
		$a_02_8 = {6a 02 57 6a fc 56 ff 15 ?? ?? ?? 00 } //1
		$a_00_9 = {43 72 65 61 74 65 54 68 72 65 61 64 00 } //1
		$a_00_10 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 00 } //1
		$a_00_11 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 00 } //1
		$a_00_12 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 00 } //1 楆摮敒潳牵散A
		$a_00_13 = {44 65 6c 65 74 65 46 69 6c 65 41 00 } //1 敄敬整楆敬A
		$a_00_14 = {53 65 74 46 69 6c 65 50 6f 69 6e 74 65 72 00 } //1
		$a_00_15 = {57 49 4e 49 4e 45 54 2e 44 4c 4c 00 } //1 䥗䥎䕎⹔䱄L
		$a_00_16 = {4d 53 56 43 50 36 30 2e 64 6c 6c 00 } //1 卍䍖㙐⸰汤l
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_02_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1) >=18
 
}