
rule Worm_Win32_Folmess_A{
	meta:
		description = "Worm:Win32/Folmess.A,SIGNATURE_TYPE_PEHSTR,04 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 73 79 73 74 65 6d 33 32 5c 74 61 73 6b 6d 64 72 2e 65 78 65 } //1 \system32\taskmdr.exe
		$a_01_1 = {5c 73 79 73 74 65 6d 33 32 5c 73 65 72 76 69 63 65 2e 65 78 65 00 00 00 4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 00 00 00 cf e0 ef ea e0 20 e8 ec e5 e5 f2 20 ed e5 e2 e5 f0 ed fb e9 20 f4 ee f0 ec e0 f2 } //1
		$a_01_2 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 4b 41 4b 54 59 43 5c } //1 C:\Documents and Settings\KAKTYC\
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 ff ff ff ff 0f 00 00 00 57 69 6e 64 6f 77 73 53 65 72 76 69 63 65 73 } //1
		$a_01_4 = {cd ee e2 e0 ff 20 ef e0 ef ea e0 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}