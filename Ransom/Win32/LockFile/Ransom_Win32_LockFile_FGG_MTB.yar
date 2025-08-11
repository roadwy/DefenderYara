
rule Ransom_Win32_LockFile_FGG_MTB{
	meta:
		description = "Ransom:Win32/LockFile.FGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 04 3e 32 85 ?? ?? ?? ?? 8b 4d e4 88 04 31 8b 45 c0 8b 7d d4 89 45 e4 8a 04 30 46 88 85 ?? ?? ?? ?? 8b 45 d8 2b c7 3b f0 72 } //5
		$a_01_1 = {4e 6f 74 47 65 74 55 70 5c 65 6e 63 72 79 70 74 5c 52 65 6c 65 61 73 65 5c 65 6e 63 72 79 70 74 2e 70 64 62 } //2 NotGetUp\encrypt\Release\encrypt.pdb
		$a_81_2 = {2e 6c 6f 63 6b 65 64 } //1 .locked
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_81_2  & 1)*1) >=8
 
}