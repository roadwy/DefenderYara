
rule Trojan_Win64_ShellcodeRunner_ARR_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b c3 49 f7 e1 49 ff c1 48 c1 ea ?? 48 ?? ?? ?? 48 2b c8 [0-05] 43 32 04 ?? 41 88 00 4c 3b ce } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win64_ShellcodeRunner_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 8a 04 13 41 80 f0 ?? 44 88 04 01 48 ff c0 48 ff c2 48 39 d7 } //8
		$a_03_1 = {48 ff c7 48 33 ce e8 ?? ?? ?? ?? ?? ?? ?? 49 0f af f5 48 ff cb } //12
	condition:
		((#a_03_0  & 1)*8+(#a_03_1  & 1)*12) >=20
 
}
rule Trojan_Win64_ShellcodeRunner_ARR_MTB_3{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 65 63 74 53 68 65 6c 6c 63 6f 64 65 52 65 6d 6f 74 65 50 72 6f 63 65 73 73 20 66 61 69 6c 65 64 3a 20 25 64 } //10 InjectShellcodeRemoteProcess failed: %d
		$a_01_1 = {53 68 65 6c 6c 63 6f 64 65 20 64 65 63 72 79 70 74 65 64 20 61 6e 64 20 77 72 69 74 74 65 6e 20 74 6f 20 30 78 25 70 } //6 Shellcode decrypted and written to 0x%p
		$a_01_2 = {4d 6f 64 33 33 2d 50 72 6f 63 45 6e 75 6d 53 68 65 6c 6c 63 6f 64 65 49 6e 6a 65 63 74 69 6f 6e 2e 70 64 62 } //4 Mod33-ProcEnumShellcodeInjection.pdb
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*6+(#a_01_2  & 1)*4) >=20
 
}