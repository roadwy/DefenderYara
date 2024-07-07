
rule VirTool_Win32_Vbcrypt_EH{
	meta:
		description = "VirTool:Win32/Vbcrypt.EH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 85 58 ff ff ff 08 00 00 00 c7 45 c0 01 00 00 00 89 75 b8 c7 85 78 ff ff ff 08 40 00 00 ff 15 90 01 04 8d 90 01 05 6a 01 8d 90 01 04 8d 90 01 04 c7 85 90 01 02 ff ff 01 00 00 00 89 b5 90 01 01 ff ff ff ff 15 90 01 05 8d 90 01 05 8d 90 01 04 ff 15 90 01 05 ff 15 90 01 1a 83 c4 10 66 3b f3 0f 8c 90 01 04 66 6b ff 40 66 8b 45 dc 0f 80 90 01 04 66 03 fe 0f 80 90 01 04 66 05 06 00 0f 80 90 01 04 66 3d 08 00 89 45 dc 0f 8c 90 01 04 0f bf f7 8d 55 dc 66 2d 08 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}