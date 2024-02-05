
rule VirTool_Win32_Vbcrypt_gen_H{
	meta:
		description = "VirTool:Win32/Vbcrypt.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 44 61 72 6b 45 79 65 5c 44 61 72 6b 65 79 65 5c 56 42 36 2e 4f 4c 42 } //01 00 
		$a_01_1 = {e9 e9 e9 e9 cc cc cc cc cc cc cc cc cc cc cc cc 9e 9e 9e 9e } //00 00 
	condition:
		any of ($a_*)
 
}