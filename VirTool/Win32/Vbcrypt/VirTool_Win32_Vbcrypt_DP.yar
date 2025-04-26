
rule VirTool_Win32_Vbcrypt_DP{
	meta:
		description = "VirTool:Win32/Vbcrypt.DP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8b 00 ff 75 08 ff 50 04 66 c7 45 e0 ?? 00 66 c7 45 e4 01 00 66 c7 45 e8 01 00 eb } //1
		$a_03_1 = {c7 45 fc 32 00 00 00 c7 85 ?? ff ff ff 16 00 00 00 c7 85 ?? ff ff ff 02 00 00 00 c7 85 ?? ff ff ff 2c 00 00 00 c7 85 ?? ff ff ff 02 00 00 00 8d 45 b0 50 } //1
		$a_03_2 = {8b 85 d8 fe ff ff 89 85 ?? ff ff ff c7 85 ?? ff ff ff 08 20 00 00 8d 95 ?? ff ff ff b9 } //1
		$a_03_3 = {c7 45 fc 3f 00 00 00 c7 85 ?? ff ff ff 05 00 00 00 c7 85 ?? ff ff ff 02 00 00 00 c7 85 ?? ff ff ff 5f 00 00 00 c7 85 ?? ff ff ff 02 00 00 00 8d 45 b0 50 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}