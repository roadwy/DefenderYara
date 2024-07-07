
rule Trojan_Win32_Picsys_PR_MTB{
	meta:
		description = "Trojan:Win32/Picsys.PR!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {70 61 73 73 77 6f 72 64 20 73 74 65 61 6c 65 72 2e 65 78 65 } //1 password stealer.exe
		$a_01_1 = {4b 61 6d 61 20 53 75 74 72 61 20 54 65 74 72 69 73 2e 65 78 65 } //1 Kama Sutra Tetris.exe
		$a_01_2 = {58 58 58 20 50 6f 72 6e 20 50 61 73 73 77 6f 72 64 73 2e 65 78 65 } //1 XXX Porn Passwords.exe
		$a_01_3 = {63 75 74 65 20 67 69 72 6c 20 67 69 76 69 6e 67 20 68 65 61 64 2e 65 78 65 } //1 cute girl giving head.exe
		$a_01_4 = {43 6f 75 6e 74 65 72 20 53 74 72 69 6b 65 20 43 44 20 4b 65 79 67 65 6e 2e 65 78 65 } //1 Counter Strike CD Keygen.exe
		$a_01_5 = {70 6c 61 79 20 73 74 61 74 69 6f 6e 20 65 6d 75 6c 61 74 6f 72 20 63 72 61 63 6b 2e 65 78 65 } //1 play station emulator crack.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}