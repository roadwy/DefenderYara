
rule Trojan_Win64_BazarLoader_AGH_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.AGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {48 89 5c 24 08 48 89 7c 24 10 55 48 8d ac 24 70 fd ff ff 48 81 ec 90 03 00 00 8b 85 c0 02 00 00 83 a5 34 01 00 00 00 89 85 30 01 00 00 48 8b 85 c8 02 } //10
		$a_80_1 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //CreateMutexA  3
		$a_80_2 = {41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //ActivateKeyboardLayout  3
		$a_80_3 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //GetKeyboardLayout  3
		$a_80_4 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 } //GetCommandLineA  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}