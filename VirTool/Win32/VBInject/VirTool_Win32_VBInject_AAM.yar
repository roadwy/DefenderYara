
rule VirTool_Win32_VBInject_AAM{
	meta:
		description = "VirTool:Win32/VBInject.AAM,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 d0 37 10 f2 } //05 00 
		$a_01_1 = {68 c2 8c 10 c5 } //01 00 
		$a_01_2 = {c7 85 70 f7 ff ff 0d 00 90 00 c7 85 68 f7 ff ff 02 00 00 00 8d 95 68 f7 ff ff 8b 45 d8 b9 86 00 00 00 2b 48 14 c1 e1 04 8b 45 d8 8b 40 0c 03 c8 } //00 00 
	condition:
		any of ($a_*)
 
}