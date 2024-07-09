
rule VirTool_Win32_Amkillz_B_MTB{
	meta:
		description = "VirTool:Win32/Amkillz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {c6 45 ee 48 c6 45 ef 3f c6 45 f0 3f c6 45 f1 3f c6 45 f2 3f c6 45 f3 74 c6 45 f4 33 c7 45 d8 11 00 00 00 } //1
		$a_02_1 = {50 8b 45 d8 50 8d 4d ?? 51 68 00 04 00 00 8d 95 ?? ?? ?? ?? 52 e8 } //1
		$a_00_2 = {8b 45 08 03 45 f8 0f b6 08 ba 01 00 00 00 6b c2 00 8b 55 10 0f b6 04 02 3b c8 } //1
		$a_00_3 = {8b 85 84 fb ff ff 50 8b 4d c0 51 ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}