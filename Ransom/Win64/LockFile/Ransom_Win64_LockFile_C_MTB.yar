
rule Ransom_Win64_LockFile_C_MTB{
	meta:
		description = "Ransom:Win64/LockFile.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {20 70 61 79 20 } //1  pay 
		$a_00_1 = {2f 72 75 73 74 63 2f } //1 /rustc/
		$a_00_2 = {64 65 63 72 79 70 74 } //1 decrypt
		$a_81_3 = {70 69 6e 67 6c 6f 63 61 6c 68 6f 73 74 2d 6e 31 3e 6e 75 6c 26 26 64 65 6c 2f 43 } //1 pinglocalhost-n1>nul&&del/C
		$a_00_4 = {6c 69 62 72 61 72 79 5c 63 6f 72 65 5c 73 72 63 5c 65 73 63 61 70 65 2e 72 73 } //1 library\core\src\escape.rs
		$a_00_5 = {72 65 61 64 6d 65 2e 74 78 74 } //1 readme.txt
		$a_00_6 = {65 6e 63 72 79 70 74 } //1 encrypt
		$a_00_7 = {64 6f 77 6e 6c 6f 61 64 } //1 download
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_81_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}