
rule Trojan_Win32_Almanahe_D{
	meta:
		description = "Trojan:Win32/Almanahe.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 37 33 c0 8a 90 90 90 01 04 80 f2 65 88 54 05 a0 40 83 f8 90 01 01 7c ed 90 00 } //1
		$a_01_1 = {41 72 70 50 6c 75 67 69 6e 2e 64 6c 6c 00 44 4c 50 49 6e 69 74 00 44 4c 50 54 65 72 6d 69 6e 61 74 65 00 44 4c 50 55 70 64 61 74 65 00 44 4c 50 56 65 72 73 69 6f 6e 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Almanahe_D_2{
	meta:
		description = "Trojan:Win32/Almanahe.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 bd 88 e6 ff ff cc cc cc cc 77 29 81 bd 88 e6 ff ff cc cc cc cc 74 5e 81 bd 88 e6 ff ff aa aa aa aa 74 1f 81 bd 88 e6 ff ff bb bb bb bb 74 32 e9 81 00 00 00 81 bd 88 e6 ff ff dd dd dd dd 74 5c } //1
		$a_01_1 = {25 73 3f 61 63 74 69 6f 6e 3d 70 6f 73 74 26 48 54 48 3d 25 75 26 48 54 4c 3d 25 75 26 50 54 3d 25 64 26 55 53 3d 25 73 26 50 57 3d 25 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}