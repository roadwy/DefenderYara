
rule Backdoor_Win32_Caphaw_AA{
	meta:
		description = "Backdoor:Win32/Caphaw.AA,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 12 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 08 89 44 24 04 8b 44 24 04 83 c4 04 3d ?? ?? ?? ?? 73 2c e8 ?? ?? 00 00 89 44 24 08 db 44 24 08 d9 fa e8 ?? ?? 00 00 03 44 24 04 89 44 24 04 8b 0c 24 41 } //100
		$a_03_1 = {89 7c 24 0c db 44 24 0c d9 fa e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b 4c 24 04 41 89 4c 24 04 81 7c 24 04 ?? ?? ?? ?? 72 } //100
		$a_03_2 = {89 4c 24 0c db 44 24 0c (d9 fa|d9 fe) e8 ?? ?? 00 00 03 44 24 08 89 44 24 08 8b 54 24 04 42 89 54 24 04 81 7c 24 04 ?? ?? ?? ?? 72 c6 } //100
		$a_03_3 = {8b 53 3c 8b ?? ?? 28 83 c4 ?? 03 c3 ff d0 } //1
		$a_03_4 = {8b 53 3c 8b 74 1a 28 03 f3 83 c4 ?? 89 75 ?? ff d6 } //1
		$a_03_5 = {8b 43 3c 8b 74 ?? 28 03 f3 83 c4 ?? 89 75 ?? ff d6 } //1
		$a_03_6 = {8b 4b 3c 8b 74 19 28 03 f3 83 c4 ?? 89 75 ?? ff d6 } //1
		$a_03_7 = {8b 4b 3c 8b 54 0b 28 83 c4 ?? 03 d3 ff d2 } //1
		$a_03_8 = {8b 43 3c 8b 4c 03 28 83 c4 ?? 03 cb ff d1 } //1
		$a_03_9 = {8b 53 3c 8b ?? ?? 28 83 c4 ?? 03 f3 ff d6 } //1
		$a_03_10 = {8b 53 3c 8b ?? ?? 28 03 ?? ff d6 } //1
		$a_03_11 = {8b 53 3c 8b ?? ?? 28 03 ?? ff d0 } //1
		$a_03_12 = {8b 45 3c 8b ?? ?? 28 03 ?? ff d1 } //1
		$a_03_13 = {8b 55 3c 8b ?? ?? 28 03 ?? ff d0 } //1
		$a_03_14 = {8b 4b 3c 8b ?? ?? 28 03 ?? ?? ?? ?? ?? ff d0 } //1
		$a_03_15 = {8b 43 3c 8b ?? ?? 28 03 ?? ?? ?? ?? ?? ?? ?? 90 13 ff d0 } //1
		$a_03_16 = {8b 43 3c 8b ?? ?? 28 03 ?? ?? ?? ?? ?? ff d0 } //1
		$a_03_17 = {8b 53 3c 8b ?? ?? 28 03 ?? ?? ?? ?? ?? ff d0 } //1
	condition:
		((#a_03_0  & 1)*100+(#a_03_1  & 1)*100+(#a_03_2  & 1)*100+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1+(#a_03_10  & 1)*1+(#a_03_11  & 1)*1+(#a_03_12  & 1)*1+(#a_03_13  & 1)*1+(#a_03_14  & 1)*1+(#a_03_15  & 1)*1+(#a_03_16  & 1)*1+(#a_03_17  & 1)*1) >=101
 
}