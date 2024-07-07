
rule Ransom_Win32_Maui_A{
	meta:
		description = "Ransom:Win32/Maui.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {4b 42 55 50 01 00 00 00 a2 00 00 00 } //1
		$a_80_1 = {6d 61 75 69 2e 6b 65 79 } //maui.key  1
		$a_80_2 = {62 79 20 3c 47 6f 64 68 65 61 64 3e 20 75 73 69 6e 67 20 2d 6d 61 75 69 20 6f 70 74 69 6f 6e } //by <Godhead> using -maui option  1
		$a_80_3 = {55 73 61 67 65 3a 20 6d 61 75 69 20 5b 2d 70 74 78 5d 20 5b 50 41 54 48 5d } //Usage: maui [-ptx] [PATH]  1
		$a_80_4 = {64 65 6d 69 67 6f 64 2e 6b 65 79 } //demigod.key  1
		$a_80_5 = {53 65 6c 66 20 4d 65 6c 74 20 28 44 65 66 61 75 6c 74 3a 20 4e 6f 29 } //Self Melt (Default: No)  1
		$a_80_6 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  1
		$a_80_7 = {45 6e 63 72 79 70 74 5b 25 73 5d 3a 20 25 73 } //Encrypt[%s]: %s  1
		$a_41_8 = {c4 1c 81 3f 54 50 52 43 75 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_41_8  & 1)*1) >=4
 
}