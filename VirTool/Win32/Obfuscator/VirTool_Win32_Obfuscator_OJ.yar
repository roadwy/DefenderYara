
rule VirTool_Win32_Obfuscator_OJ{
	meta:
		description = "VirTool:Win32/Obfuscator.OJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 d2 4f 24 7d 38 } //01 00 
		$a_01_1 = {69 d2 9a fa 21 12 } //01 00 
		$a_01_2 = {81 c1 43 aa 35 43 } //01 00 
		$a_01_3 = {81 f2 c3 db 99 2a } //00 00 
	condition:
		any of ($a_*)
 
}