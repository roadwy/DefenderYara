
rule VirTool_Win32_VBInject_gen_JJ{
	meta:
		description = "VirTool:Win32/VBInject.gen!JJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 00 55 89 e5 8b a1 90 01 04 c7 40 04 75 08 8b 4d 6a 04 58 d1 e0 8b 0d 90 00 } //01 00 
		$a_03_1 = {83 c4 1c a1 90 01 04 33 c9 2b 48 14 a1 90 01 04 8b 40 0c c7 04 c8 fd 0a b7 01 83 64 c8 04 00 a1 90 01 04 6a 01 59 2b 48 14 a1 90 01 04 8b 40 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}