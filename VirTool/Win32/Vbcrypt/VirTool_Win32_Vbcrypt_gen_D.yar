
rule VirTool_Win32_Vbcrypt_gen_D{
	meta:
		description = "VirTool:Win32/Vbcrypt.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 0e 5a 01 90 } //01 00 
		$a_01_1 = {0e 65 00 74 b4 6e 09 49 cd } //01 00 
		$a_01_2 = {cd 46 21 74 54 65 68 53 69 } //00 00 
	condition:
		any of ($a_*)
 
}