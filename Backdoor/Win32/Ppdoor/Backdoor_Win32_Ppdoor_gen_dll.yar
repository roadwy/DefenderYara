
rule Backdoor_Win32_Ppdoor_gen_dll{
	meta:
		description = "Backdoor:Win32/Ppdoor.gen!dll,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 08 00 00 "
		
	strings :
		$a_02_0 = {83 c4 08 83 f8 01 74 4d 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 04 e8 ?? ?? 00 00 b8 01 00 00 00 81 c4 00 02 00 00 c2 0c 00 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 04 e8 ?? ?? 00 00 b8 01 00 00 00 81 c4 00 02 00 00 c2 0c 00 68 ?? ?? ?? ?? e8 ?? ?? 00 00 83 c4 04 b8 01 00 00 00 81 c4 00 02 00 00 c2 0c 00 } //10
		$a_02_1 = {8b 4c 24 14 8b 54 24 12 8b 44 24 10 81 e1 ff ff 00 00 81 e2 ff ff 00 00 51 25 ff ff 00 00 52 50 8d 4c 24 64 68 ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 8d 54 24 6c 52 56 e8 ?? ?? ff ff 83 c4 1c 57 56 e8 ?? ?? ff ff 83 c4 08 56 ff 15 ?? ?? ?? ?? 5f 5e 81 c4 50 01 00 00 c3 } //10
		$a_02_2 = {51 c7 44 24 3c 44 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 39 8b 3d ?? ?? ?? ?? 56 33 f6 8b 54 24 08 52 e8 ?? ?? ff ff 83 c4 04 83 f8 02 75 0a 6a 64 ff d7 46 83 fe 64 7c e4 8b c6 5e 83 e8 64 5f f7 d8 1b c0 24 fe 83 c0 03 83 c4 54 c3 b8 02 00 00 00 5f 83 c4 54 c3 } //10
		$a_00_3 = {63 3a 5c 74 6d 70 25 6c 64 2e 64 61 74 } //2 c:\tmp%ld.dat
		$a_00_4 = {25 30 32 64 2e 25 30 32 64 3a 25 30 32 64 } //2 %02d.%02d:%02d
		$a_00_5 = {5b 4c 4f 41 44 5f } //2 [LOAD_
		$a_00_6 = {44 6c 6c 4d 61 69 6e 28 44 4c 4c 5f 50 52 4f 43 45 53 53 5f 44 45 54 41 43 48 29 } //2 DllMain(DLL_PROCESS_DETACH)
		$a_00_7 = {53 52 56 5f 4c 4f 41 44 45 52 } //2 SRV_LOADER
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2) >=30
 
}