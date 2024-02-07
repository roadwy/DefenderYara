
rule VirTool_Win32_Vbcrypt_K{
	meta:
		description = "VirTool:Win32/Vbcrypt.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 00 69 00 6c 00 6c 00 61 00 72 00 20 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 } //01 00  Billar Crypter
		$a_01_1 = {45 6e 63 72 69 70 74 61 41 50 49 00 72 75 6e 00 53 74 75 62 64 6f 73 } //01 00 
		$a_01_2 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}