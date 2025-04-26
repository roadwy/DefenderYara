
rule VirTool_Win32_Toksteal_B{
	meta:
		description = "VirTool:Win32/Toksteal.B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 52 6a 00 ff 15 ?? ?? ?? ?? 8d 45 b4 50 6a 00 68 ff 01 0f 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? eb 06 8b 4d 08 89 4d b4 8d 55 fc 52 6a 01 6a 02 6a 00 68 00 00 00 02 8b 45 b4 50 ff 15 } //10
		$a_01_1 = {2d 2d 3e 46 6f 75 6e 64 20 53 59 53 54 45 4d 20 74 6f 6b 65 6e 20 30 78 25 78 } //2 -->Found SYSTEM token 0x%x
		$a_01_2 = {2d 2d 3e 46 6f 75 6e 64 20 25 73 20 54 6f 6b 65 6e } //2 -->Found %s Token
		$a_01_3 = {44 75 70 6c 69 63 61 74 65 54 6f 6b 65 6e } //2 DuplicateToken
		$a_01_4 = {44 74 63 47 65 74 54 72 61 6e 73 61 63 74 69 6f 6e 4d 61 6e 61 67 65 72 45 78 41 } //2 DtcGetTransactionManagerExA
		$a_01_5 = {4e 45 54 57 4f 52 4b 20 53 45 52 56 49 43 45 00 } //2 䕎坔剏⁋䕓噒䍉E
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=10
 
}