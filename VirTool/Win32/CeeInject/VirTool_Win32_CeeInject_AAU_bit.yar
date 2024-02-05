
rule VirTool_Win32_CeeInject_AAU_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AAU!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 0f 8a 8d 90 01 04 8b 55 08 80 f1 90 01 01 88 4a 02 90 00 } //01 00 
		$a_03_1 = {8d 0c 80 c1 e1 03 8b d1 c1 e9 02 8d bd 90 01 04 f3 a5 8b ca 83 e1 03 f3 a4 90 00 } //01 00 
		$a_03_2 = {32 da 88 19 8b 8d 90 01 04 8a 94 29 90 01 04 8b 85 90 01 04 8a 8c 28 90 01 04 8d 84 28 90 01 04 32 ca 88 08 90 00 } //01 00 
		$a_03_3 = {8a 19 8a 94 2a 90 01 04 32 da 88 19 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}