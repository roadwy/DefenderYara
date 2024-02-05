
rule VirTool_Win32_Vbcrypt_EG{
	meta:
		description = "VirTool:Win32/Vbcrypt.EG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 15 04 10 40 00 50 ff 15 18 11 40 00 50 8d 90 02 60 c7 85 90 01 02 ff ff 90 01 01 00 00 00 c7 85 90 01 02 ff ff 02 00 00 00 c7 85 90 02 ff ff 90 01 01 00 00 00 c7 85 90 02 ff ff 02 00 00 00 6a 00 8d 90 01 06 8d 90 01 06 ff 15 90 01 04 8d 90 01 06 8d 90 01 06 8d 90 01 06 ff 15 90 00 } //01 00 
		$a_03_1 = {40 db e2 89 85 90 01 04 83 bd 90 01 04 00 7d 23 6a 40 68 90 01 1e 90 13 8d 90 02 20 ff 15 90 01 05 8d 90 01 06 8d 90 01 06 ff 15 90 01 05 8d 90 01 06 8d 90 01 06 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}