
rule VirTool_Win32_VBInject_BAK_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAK!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 5e 82 12 00 90 02 30 05 f8 7d 2f 00 90 02 30 39 01 90 02 30 0f 85 4f fe ff ff 90 02 30 83 e9 04 90 02 30 68 21 14 20 00 90 02 30 58 90 02 30 05 2c ec 32 00 90 02 30 8b 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}