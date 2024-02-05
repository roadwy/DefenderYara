
rule VirTool_Win32_VBInject_gen_DD{
	meta:
		description = "VirTool:Win32/VBInject.gen!DD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {94 70 fc 1c 00 94 70 fc 10 00 aa 71 9c fd } //01 00 
		$a_00_1 = {e7 80 0c 00 4a ae 0b 23 00 04 00 23 28 ff 2a } //01 00 
		$a_01_2 = {3a 00 3b 00 54 00 4d 00 56 00 5a 00 4d 00 53 00 } //01 00 
	condition:
		any of ($a_*)
 
}