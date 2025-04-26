
rule VirTool_Win32_Vbcrypt_DG{
	meta:
		description = "VirTool:Win32/Vbcrypt.DG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 b8 8d 55 d0 52 50 8b 08 8b f0 ff 51 58 85 c0 } //1
		$a_01_1 = {ff d3 8b d0 8d 4d cc ff d7 8b 55 d0 50 52 ff d3 8b d0 8d 4d c8 ff d7 50 68 } //1
		$a_01_2 = {8d 55 dc 52 ff d6 8d 45 d8 50 ff d6 8d 4d c0 8d 55 c4 51 8d 45 c8 52 8d 4d cc 50 8d 55 d0 51 8d 45 d4 52 50 6a 06 ff } //1
		$a_01_3 = {8b d0 8d 4d cc ff d7 8b 4d d0 50 51 ff d3 8b d0 8d 4d c8 ff d7 50 68 68 1b 40 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}