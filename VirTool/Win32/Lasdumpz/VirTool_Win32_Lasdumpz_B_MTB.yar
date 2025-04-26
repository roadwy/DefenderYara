
rule VirTool_Win32_Lasdumpz_B_MTB{
	meta:
		description = "VirTool:Win32/Lasdumpz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b8 ff 0f 0f 00 4c 89 7d ?? 48 8d 55 ?? c7 45 ?? 1a 00 1c 00 } //10
		$a_00_1 = {53 00 45 00 43 00 55 00 52 00 49 00 54 00 59 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 79 00 5c 00 53 00 65 00 63 00 72 00 65 00 74 00 73 00 5c 00 5f 00 5f 00 47 00 54 00 5f 00 5f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 } //10 SECURITY\Policy\Secrets\__GT__Decrypt
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}