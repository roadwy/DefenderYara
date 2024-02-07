
rule Ransom_Win32_LockScreen_O{
	meta:
		description = "Ransom:Win32/LockScreen.O,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 65 6c 6c 6f 70 00 00 ff ff ff ff } //01 00 
		$a_01_1 = {62 65 6c 6c 69 73 73 69 6d 6d 6f 00 ff ff ff ff } //01 00 
		$a_01_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_01_3 = {6e 75 6d 00 } //01 00  畮m
		$a_01_4 = {70 61 6c 6f 00 } //02 00 
		$a_01_5 = {4d 49 43 52 4f 53 4f 46 54 20 53 59 53 54 45 4d 20 53 45 43 55 52 49 54 59 00 } //02 00  䥍剃协䙏⁔奓呓䵅匠䍅剕呉Y
		$a_01_6 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 5c 00 } //02 00 
		$a_01_7 = {55 ad 4c fc 48 2b 3f af 4d 52 50 9e 3a 8a 4b 89 3e d6 55 64 46 98 62 12 5c 1e 6b 73 68 4e 6c 0b 68 32 5f 07 6d af 55 c2 48 57 6e f6 6d 77 65 0f 68 72 68 06 64 77 19 e3 3e 60 71 a4 69 5c 6b d8 5e f1 6c 28 6c be 55 33 00 00 00 00 ff ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}