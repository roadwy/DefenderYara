
rule VirTool_Win32_Obfuscator_VX{
	meta:
		description = "VirTool:Win32/Obfuscator.VX,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_13_0 = {bb e8 03 00 00 90 02 20 e8 90 16 64 a1 18 00 00 00 8b d2 8b d2 90 00 01 } //00 07 
		$a_8b_1 = {c0 c0 02 8b d2 00 00 5d 04 00 00 c9 99 02 80 5c 22 } //00 00 
	condition:
		any of ($a_*)
 
}