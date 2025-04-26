
rule VirTool_Win32_Vbcrypt_CT{
	meta:
		description = "VirTool:Win32/Vbcrypt.CT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 95 70 ff ff ff 8d 45 dc 52 50 89 bd 78 ff ff ff 89 bd 70 ff ff ff ff d3 8b 4d 0c 50 8b 11 52 } //1
		$a_03_1 = {c7 85 c0 fe ff ff ?? ?? 40 00 eb 0a c7 85 c0 fe ff ff ?? ?? 40 00 8b 95 c0 fe ff ff 8b 02 89 85 08 ff ff ff 8d 4d c0 51 8b 95 08 ff ff ff 8b 02 8b 8d 08 ff ff ff 51 } //1
		$a_03_2 = {83 c4 14 0f bf 95 bc fe ff ff 85 d2 0f 84 55 1d 00 00 c7 45 fc 04 00 00 00 e8 ?? ?? ff ff c7 45 fc 05 00 00 00 83 3d ?? ?? 40 00 00 75 1c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}