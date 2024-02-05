
rule VirTool_Win32_VBInject_AFI{
	meta:
		description = "VirTool:Win32/VBInject.AFI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 04 c1 5b 0c 8b 5b 8b 95 90 01 02 ff ff 8d 8d 90 01 02 ff ff c7 44 c2 04 0c 31 c0 66 90 00 } //01 00 
		$a_03_1 = {8b 4d 10 66 2b 01 0f 80 90 01 04 0f bf d0 90 00 } //01 00 
		$a_03_2 = {6a 6e 51 ff d7 8d 90 01 02 6a 78 52 ff d7 8d 90 01 02 6a 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}