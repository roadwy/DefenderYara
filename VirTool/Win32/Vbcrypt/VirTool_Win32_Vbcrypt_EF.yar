
rule VirTool_Win32_Vbcrypt_EF{
	meta:
		description = "VirTool:Win32/Vbcrypt.EF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 51 c7 85 60 ff ff ff 03 80 00 00 ff 15 90 01 04 66 85 c0 90 13 90 02 10 52 50 89 bd 90 01 04 89 bd 90 01 04 ff d3 8b 4d 0c 50 8b 11 52 ff 15 90 01 2d 50 ff 15 90 01 16 66 8b 4d 90 01 01 8d 55 90 01 01 66 89 8d 90 01 04 8d 85 90 01 04 52 8d 8d 90 01 04 50 51 89 bd 90 01 04 ff 15 90 01 4e 52 50 ff 15 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}