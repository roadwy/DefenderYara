
rule Ransom_Win32_Crybisec_A{
	meta:
		description = "Ransom:Win32/Crybisec.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0e 00 00 "
		
	strings :
		$a_00_0 = {2f 69 6e 76 6f 6b 65 2e 70 68 70 3f 70 72 65 66 69 78 3d 25 64 00 } //2
		$a_00_1 = {2f 75 70 6c 6f 61 64 2e 70 68 70 3f 69 64 3d 25 73 26 66 69 6c 65 6e 61 6d 65 3d 25 73 5f 25 53 00 } //2
		$a_00_2 = {62 6f 74 69 64 3d 25 73 00 } //1
		$a_00_3 = {6c 61 6e 67 69 64 3d 25 64 00 } //1 慬杮摩┽d
		$a_00_4 = {70 75 72 73 65 3d 25 73 00 } //1
		$a_00_5 = {72 63 34 6b 65 79 00 } //1
		$a_00_6 = {77 69 6e 76 65 72 3d 25 64 2e 25 64 2e 25 64 00 } //1
		$a_00_7 = {2a 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 2a 00 2e 00 2a 00 00 00 } //1
		$a_00_8 = {5c 00 77 00 73 00 5f 00 61 00 75 00 64 00 69 00 6f 00 5f 00 65 00 61 00 78 00 33 00 32 00 00 00 } //1
		$a_00_9 = {48 00 6f 00 77 00 54 00 6f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74 00 00 00 } //1
		$a_00_10 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 73 00 72 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00 } //1
		$a_00_11 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 20 00 76 00 73 00 73 00 00 00 } //1
		$a_01_12 = {e8 14 00 00 00 52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 00 48 f7 d2 68 59 36 fb db } //2
		$a_01_13 = {8b 12 31 c8 83 f7 10 31 ff 01 d0 09 d6 81 45 e4 87 00 00 00 39 da 75 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_01_12  & 1)*2+(#a_01_13  & 1)*2) >=10
 
}