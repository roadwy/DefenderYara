
rule HackTool_Win64_EasyKatz{
	meta:
		description = "HackTool:Win64/EasyKatz,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {0f 1f 40 00 0f 1f 84 00 00 00 00 00 48 8d 54 24 7c 49 8b c6 0f 1f 84 00 00 00 00 00 0f b7 0c 42 66 3b 0c 47 75 1d 0f b7 4c 42 02 66 3b 4c 47 02 75 11 48 83 c0 02 48 83 f8 0a 75 e0 44 8b 44 24 58 eb 1e 48 8d 54 24 50 48 8b cb ff 15 90 01 04 85 c0 75 b7 48 8b cb ff 15 90 01 04 45 8b c6 33 d2 b9 10 04 00 00 ff 15 90 01 04 48 8b f0 48 83 f8 ff 75 0c 90 00 } //5
		$a_80_1 = {5b 2a 5d 20 6c 73 61 73 73 2e 65 78 65 20 66 6f 75 6e 64 20 61 74 20 25 70 } //[*] lsass.exe found at %p  1
		$a_80_2 = {5b 2a 5d 20 77 64 69 67 65 73 74 2e 64 6c 6c 20 66 6f 75 6e 64 20 61 74 20 25 70 } //[*] wdigest.dll found at %p  1
		$a_80_3 = {5b 2a 5d 20 6c 73 61 73 72 76 2e 64 6c 6c 20 66 6f 75 6e 64 20 61 74 20 25 70 } //[*] lsasrv.dll found at %p  1
		$a_80_4 = {5b 2a 5d 20 4c 6f 61 64 65 64 20 6c 73 61 73 72 76 2e 64 6c 6c 20 61 74 20 61 64 64 72 65 73 73 20 25 70 } //[*] Loaded lsasrv.dll at address %p  1
		$a_80_5 = {5b 2a 5d 20 43 72 65 64 65 6e 74 69 61 6c 73 20 69 6e 63 6f 6d 69 6e 67 } //[*] Credentials incoming  1
		$a_80_6 = {5b 2a 5d 20 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 49 64 20 3a 20 25 64 20 3b 20 25 64 20 28 25 30 38 78 3a 25 30 38 78 29 } //[*] Authentication Id : %d ; %d (%08x:%08x)  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}