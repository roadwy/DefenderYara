
rule TrojanDownloader_Win32_Delf_RAY{
	meta:
		description = "TrojanDownloader:Win32/Delf.RAY,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {3f 61 64 76 3d } //1 ?adv=
		$a_01_1 = {69 6e 74 65 72 6e 61 74 2e 64 6c 6c 2c 4c 6f 61 64 4b 65 79 62 6f 61 72 64 50 72 6f 66 69 6c 65 } //1 internat.dll,LoadKeyboardProfile
		$a_01_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_02_3 = {88 58 03 8d 45 ?? 8b 15 ?? ?? ?? ?? 8a 52 03 e8 ?? ?? ff ff 8b 45 ?? e8 ?? ?? ff ff bb 73 00 00 00 2b d8 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 88 58 06 b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ff ff } //10
		$a_02_4 = {55 8b ec 81 c4 a8 fa ff ff 53 56 57 8b fa 8b d8 8d 75 f4 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 fc 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 6a 00 68 00 00 00 80 6a 00 6a 00 8b c3 e8 ?? ?? ff ff 50 8b 45 fc 50 e8 ?? ?? ff ff 89 45 f8 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8b d7 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*10+(#a_02_4  & 1)*10) >=22
 
}