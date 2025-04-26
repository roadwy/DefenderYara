
rule Trojan_Win64_ShellCodeRunner_GB_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 50 45 42 } //1 main.PEB
		$a_01_1 = {6d 61 69 6e 2e 49 4d 41 47 45 5f 44 4f 53 5f 48 45 41 44 45 52 } //1 main.IMAGE_DOS_HEADER
		$a_01_2 = {6d 61 69 6e 2e 49 4d 41 47 45 5f 46 49 4c 45 5f 48 45 41 44 45 52 } //1 main.IMAGE_FILE_HEADER
		$a_01_3 = {6d 61 69 6e 2e 49 4d 41 47 45 5f 4f 50 54 49 4f 4e 41 4c 5f 48 45 41 44 45 52 33 32 } //1 main.IMAGE_OPTIONAL_HEADER32
		$a_01_4 = {6d 61 69 6e 2e 49 4d 41 47 45 5f 4f 50 54 49 4f 4e 41 4c 5f 48 45 41 44 45 52 36 34 } //1 main.IMAGE_OPTIONAL_HEADER64
		$a_01_5 = {6d 61 69 6e 2e 50 52 4f 43 45 53 53 5f 42 41 53 49 43 5f 49 4e 46 4f 52 4d 41 54 49 4f 4e } //1 main.PROCESS_BASIC_INFORMATION
		$a_01_6 = {73 68 65 6c 6c 63 6f 64 65 } //1 shellcode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}