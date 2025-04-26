
rule Ransom_Win32_Higuniel_B{
	meta:
		description = "Ransom:Win32/Higuniel.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 21 } //2 All your files have been encrypted !
		$a_01_1 = {49 66 20 79 6f 75 20 77 61 6e 74 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 66 69 6c 65 73 20 77 72 69 74 65 20 6f 6e 20 65 6d 61 69 6c 20 2d 20 74 77 69 73 74 40 61 69 72 6d 61 69 6c 2e 63 63 } //2 If you want restore your files write on email - twist@airmail.cc
		$a_01_2 = {49 66 20 79 6f 75 20 77 61 6e 74 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 66 69 6c 65 73 20 77 72 69 74 65 20 6f 6e 20 65 6d 61 69 6c 20 2d 20 62 6c 69 6e 64 40 61 69 72 6d 61 69 6c 2e 63 63 } //2 If you want restore your files write on email - blind@airmail.cc
		$a_81_3 = {48 6f 77 5f 44 65 63 72 79 70 74 5f 46 69 6c 65 73 2e 74 78 74 } //2 How_Decrypt_Files.txt
		$a_01_4 = {2e 00 5b 00 74 00 77 00 69 00 73 00 74 00 40 00 61 00 69 00 72 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 63 00 5d 00 2e 00 74 00 77 00 69 00 73 00 74 00 } //2 .[twist@airmail.cc].twist
		$a_01_5 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //2 vssadmin.exe Delete Shadows /All /Quiet
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_81_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=8
 
}