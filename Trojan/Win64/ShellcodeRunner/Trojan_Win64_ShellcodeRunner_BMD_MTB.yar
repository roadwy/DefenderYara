
rule Trojan_Win64_ShellcodeRunner_BMD_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 0f b6 00 89 c1 48 8b 45 f8 ba 00 00 00 00 48 f7 75 f0 48 8d 05 b4 27 00 00 0f ?? ?? 02 31 c1 48 8b 55 10 48 8b 45 f8 48 01 d0 89 ca 88 10 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_ShellcodeRunner_BMD_MTB_2{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_03_0 = {48 01 d0 44 0f b6 00 48 8b 45 ?? ba ?? ?? ?? ?? 48 f7 75 } //2
		$a_03_1 = {48 01 d0 0f b6 08 48 8b 55 ?? 48 8b 45 ?? 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 } //2
		$a_01_2 = {44 65 63 6f 64 69 6e 67 20 42 61 73 65 36 34 20 70 61 79 6c 6f 61 64 20 28 53 69 7a 65 3a 20 25 64 29 2e 2e 2e } //2 Decoding Base64 payload (Size: %d)...
		$a_01_3 = {53 65 74 74 69 6e 67 20 50 65 72 73 69 73 74 65 6e 63 65 20 28 41 75 74 6f 52 75 6e 29 2e 2e 2e } //2 Setting Persistence (AutoRun)...
		$a_01_4 = {58 4f 52 2d 69 6e 67 20 44 4c 4c 20 6e 61 6d 65 20 73 74 72 69 6e 67 2e 2e 2e } //2 XOR-ing DLL name string...
		$a_01_5 = {44 65 6c 65 74 69 6e 67 20 61 73 73 6f 63 69 61 74 65 64 20 66 69 6c 65 3a 20 25 73 } //2 Deleting associated file: %s
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}