
rule VirTool_Win32_Vbcrypt_EB{
	meta:
		description = "VirTool:Win32/Vbcrypt.EB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d6 8d 4d 80 6a 6c 51 ff d6 8d 95 60 ff ff ff 6a 58 52 ff d6 8d 85 40 ff ff ff 6a 78 50 ff d6 8d 8d 20 ff ff ff 6a 5a 51 ff d6 6a 71 8d 95 00 ff ff ff 52 ff d6 8d 85 e0 fe ff ff 6a 33 50 ff d6 8d 8d c0 fe ff ff 6a 69 51 ff d6 8d 95 a0 fe ff ff 6a 53 52 ff d6 8d 85 80 fe ff ff 6a 42 50 ff d6 8d 8d 60 fe ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}