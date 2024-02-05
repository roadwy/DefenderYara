
rule VirTool_Win32_CeeInject_NN_bit{
	meta:
		description = "VirTool:Win32/CeeInject.NN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 04 4a 8b 8d 90 01 04 0f af 8d 90 01 04 8b 95 90 01 04 2b 95 90 01 04 03 ca 03 c1 8b 0d 90 01 04 03 8d 90 01 04 88 01 90 00 } //01 00 
		$a_03_1 = {83 c4 08 8b cb 33 f6 66 d1 e8 66 d1 e0 8b 0d 90 01 04 97 8b d9 93 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}