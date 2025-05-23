
rule PWS_Win32_Jauxeer_A{
	meta:
		description = "PWS:Win32/Jauxeer.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {0f b7 8d a2 fb ff ff 0f b7 95 aa fb ff ff 8b c1 8d 8d b0 fd ff ff 03 c0 8d 04 80 03 d0 42 52 8d 95 b0 fe ff ff 52 68 ?? ?? 44 00 51 e8 ?? ?? 00 00 } //2
		$a_00_1 = {5c 52 65 63 79 63 6c 65 64 } //1 \Recycled
		$a_00_2 = {25 73 5c 25 64 25 64 2e 64 61 74 } //1 %s\%d%d.dat
		$a_00_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 73 } //1 rundll32.exe %s s
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}
rule PWS_Win32_Jauxeer_A_2{
	meta:
		description = "PWS:Win32/Jauxeer.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 0c 00 00 "
		
	strings :
		$a_03_0 = {68 00 01 00 00 52 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 45 fc 39 30 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 f8 03 75 } //5
		$a_01_1 = {2b 45 dc 3d 10 27 00 00 0f 87 } //3
		$a_01_2 = {26 76 65 72 3d 25 73 26 74 67 69 64 3d 25 73 26 61 64 64 72 65 73 73 3d 25 73 } //2 &ver=%s&tgid=%s&address=%s
		$a_01_3 = {65 3a 00 45 3a 5c 00 25 2e 38 78 25 2e 38 78 25 } //1 㩥䔀尺─㠮╸㠮╸
		$a_01_4 = {33 36 30 73 61 66 65 00 5c 33 36 30 5c } //1
		$a_01_5 = {6f 6c 6c 79 64 62 67 2e 69 6e 69 00 4c 69 62 63 } //1
		$a_01_6 = {2d 4c 65 6e 67 74 68 3a 00 0d 0a 00 25 64 00 43 3a 5c } //1
		$a_01_7 = {3c 2f 25 73 3e 00 3f 43 49 44 3d } //1
		$a_01_8 = {2e 61 73 70 00 72 62 00 4d 5a 00 } //1
		$a_01_9 = {77 62 2b 00 5b 56 45 52 5d } //1
		$a_01_10 = {5b 43 49 44 5d 00 53 6f 66 74 77 61 72 65 } //1 䍛䑉]潓瑦慷敲
		$a_01_11 = {66 3d 25 73 26 6d 3d 25 73 } //1 f=%s&m=%s
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=9
 
}