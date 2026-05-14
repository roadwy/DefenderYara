
rule Trojan_Win64_ShellcodeRunner_GPP_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.GPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 74 68 65 67 69 6f 69 70 68 6f 6e 67 74 68 75 79 74 68 61 6e 68 6c 69 65 6e 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 } //1 //thegioiphongthuythanhlien.com/wp-content/plugins
		$a_01_1 = {5c 73 68 65 6c 6c 63 6f 64 65 36 34 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 73 68 65 6c 6c 63 6f 64 65 36 34 2e 70 64 62 } //1 \shellcode64\x64\Release\shellcode64.pdb
		$a_00_2 = {43 00 3a 00 5c 00 49 00 4e 00 54 00 45 00 52 00 4e 00 41 00 4c 00 5c 00 52 00 45 00 4d 00 4f 00 54 00 45 00 2e 00 45 00 58 00 45 00 } //1 C:\INTERNAL\REMOTE.EXE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}