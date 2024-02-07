
rule VirTool_Win32_VBInject_FQ{
	meta:
		description = "VirTool:Win32/VBInject.FQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8b 45 90 01 01 99 6a 05 5e f7 fe 83 c2 02 0f 80 90 01 02 00 00 33 ca 90 00 } //01 00 
		$a_03_1 = {66 0f b6 08 8b 45 84 8b 55 90 01 01 66 33 0c 42 90 00 } //01 00 
		$a_01_2 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 00 } //00 00  瑒䵬癯䵥浥牯y
	condition:
		any of ($a_*)
 
}