
rule VirTool_Win32_Vbcrypt_DN{
	meta:
		description = "VirTool:Win32/Vbcrypt.DN,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 07 00 00 "
		
	strings :
		$a_03_0 = {03 85 64 ff ff ff 89 45 ?? 8b 45 ?? 3b 85 60 ff ff ff 7f } //1
		$a_03_1 = {8b d8 8b 45 0c ff 30 f7 db 1b db f7 db e8 ?? ?? ff ff f7 d8 1b c0 f7 d8 85 d8 } //1
		$a_01_2 = {56 8d 45 e4 89 45 c8 6a 40 8d 45 c0 50 8d 45 d4 50 c7 45 c0 11 60 00 00 } //1
		$a_01_3 = {89 45 e4 56 8d 45 d8 89 45 bc 68 80 00 00 00 8d 45 b4 50 8d 45 c8 50 } //1
		$a_01_4 = {57 6a 09 6a 01 57 8d 85 54 ff ff ff 50 6a 10 68 80 08 00 00 e8 } //1
		$a_02_5 = {53 68 aa 00 00 00 6a 01 53 8d 45 b0 50 6a 10 68 80 08 00 00 e8 ?? ?? ff ff } //1
		$a_02_6 = {83 c4 14 eb 52 b8 ?? ?? ?? ?? f7 d8 b9 ?? ?? ?? ?? 83 d1 00 f7 d9 89 ?? ?? ff ff ff 89 ?? ?? ff ff ff 6a 00 6a 00 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1) >=3
 
}