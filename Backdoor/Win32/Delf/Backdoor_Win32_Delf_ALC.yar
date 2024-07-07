
rule Backdoor_Win32_Delf_ALC{
	meta:
		description = "Backdoor:Win32/Delf.ALC,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 00 47 61 79 2d 4c 65 73 62 69 61 6e 2d 50 68 6f 74 6f 00 00 00 ff ff ff ff 0a 00 00 00 68 69 64 65 20 31 30 30 30 30 00 00 ff ff ff ff 38 00 00 00 63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 47 61 79 2d 4c 65 73 62 69 61 6e 2d 50 68 6f 74 6f 5c 47 61 79 2d 4c 65 73 62 69 61 6e 2d 50 68 6f 74 6f 2e 65 78 65 00 } //3
		$a_01_1 = {68 74 74 70 3a 2f 2f 6e 65 6f 73 61 70 2e 72 75 2f 00 00 00 ff ff ff ff 16 00 00 00 68 74 74 70 3a 2f 2f 73 75 70 65 72 2d 74 64 73 2e 69 6e 66 6f 2f 00 00 ff ff ff ff 17 00 00 00 68 74 74 70 3a 2f 2f 69 31 69 69 31 69 69 31 31 69 2e 69 6e 66 6f 2f 00 ff ff ff ff 16 00 00 00 68 74 74 70 3a 2f 2f 31 69 69 31 69 31 69 69 31 31 2e 63 6f 6d 2f 00 00 ff ff ff ff 15 00 00 00 68 74 74 70 3a 2f 2f 69 75 31 31 75 69 31 69 6c 6c 2e 77 73 2f 00 00 00 ff ff ff ff 0e 00 00 00 68 74 74 70 3a 2f 2f 78 65 70 2e 72 75 2f } //3
		$a_01_2 = {75 69 6e 2e 74 78 74 00 ff ff ff ff 0a 00 00 00 64 64 2e 6d 6d 2e 79 79 79 79 00 00 ff ff ff ff 0b 00 00 00 74 65 73 74 73 70 72 66 31 32 33 } //2
		$a_01_3 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 47 61 79 2d 4c 65 73 62 69 61 6e 2d 50 68 6f 74 6f } //1 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Gay-Lesbian-Photo
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=8
 
}