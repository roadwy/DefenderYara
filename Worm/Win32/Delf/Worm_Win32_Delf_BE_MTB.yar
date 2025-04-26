
rule Worm_Win32_Delf_BE_MTB{
	meta:
		description = "Worm:Win32/Delf.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 44 41 43 20 52 6f 75 74 65 6e 70 6c 61 6e 65 72 20 32 30 30 35 2d 32 30 30 36 5f 6b 65 79 67 65 6e 2e 65 78 65 } //1 ADAC Routenplaner 2005-2006_keygen.exe
		$a_01_1 = {41 67 65 20 4f 66 20 4d 79 74 68 6f 6c 6f 67 79 20 6e 6f 20 63 64 20 63 72 61 63 6b 2e 65 78 65 } //1 Age Of Mythology no cd crack.exe
		$a_01_2 = {45 6d 70 69 72 65 5f 41 74 5f 57 61 72 5f 4e 4f 43 44 5f 43 72 61 63 6b 2e 65 78 65 } //1 Empire_At_War_NOCD_Crack.exe
		$a_01_3 = {46 2e 45 2e 41 2e 52 20 43 44 20 61 6e 64 20 45 58 45 20 43 72 61 63 6b 2b 6b 65 79 67 65 6e 2e 65 78 65 } //1 F.E.A.R CD and EXE Crack+keygen.exe
		$a_01_4 = {41 6e 69 6d 61 74 69 6f 6e 20 57 6f 72 6b 73 68 6f 70 20 4b 65 79 47 65 6e 2e 65 78 65 } //1 Animation Workshop KeyGen.exe
		$a_01_5 = {48 61 72 72 79 20 50 6f 74 74 65 72 20 61 6e 64 20 54 68 65 20 53 6f 72 63 65 72 65 72 73 20 53 74 6f 6e 65 20 6e 6f 20 63 64 20 63 72 61 63 6b 2e 65 78 65 } //1 Harry Potter and The Sorcerers Stone no cd crack.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}