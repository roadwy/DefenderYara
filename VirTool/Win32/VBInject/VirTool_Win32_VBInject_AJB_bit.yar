
rule VirTool_Win32_VBInject_AJB_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 7c 24 04 57 68 90 01 04 59 51 f3 a4 59 5f 68 90 01 04 31 f6 5b 31 1c 0f 90 00 } //01 00 
		$a_01_1 = {c7 45 50 04 00 00 00 81 f9 00 00 00 aa 75 e8 eb 5f } //01 00 
		$a_01_2 = {66 c7 45 50 04 00 81 f9 00 00 00 aa 75 e9 eb 5f } //00 00 
	condition:
		any of ($a_*)
 
}