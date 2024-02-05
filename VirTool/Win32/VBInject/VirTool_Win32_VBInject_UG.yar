
rule VirTool_Win32_VBInject_UG{
	meta:
		description = "VirTool:Win32/VBInject.UG,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 d0 37 10 f2 } //05 00 
		$a_01_1 = {68 88 fe b3 16 } //05 00 
		$a_01_2 = {68 c2 8c 10 c5 } //01 00 
		$a_03_3 = {ff ff c1 00 00 00 90 09 04 00 c7 85 90 00 } //01 00 
		$a_03_4 = {ff ff cf 00 00 00 90 09 04 00 c7 85 90 00 } //01 00 
		$a_03_5 = {ff ff 0d 00 00 00 90 09 04 00 c7 85 90 00 } //01 00 
		$a_03_6 = {ff ff 0d 00 00 90 90 90 09 04 00 c7 85 90 00 } //01 00 
		$a_03_7 = {ff ff e7 00 00 00 90 09 04 00 c7 85 90 00 } //01 00 
		$a_03_8 = {ff ff 4e 00 00 00 90 09 04 00 c7 85 90 00 } //00 00 
		$a_00_9 = {80 10 00 00 77 70 3b 02 64 ac 50 25 97 a2 f1 3a } //c0 b8 
	condition:
		any of ($a_*)
 
}