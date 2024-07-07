
rule VirTool_Win32_VBInject_BAW_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAW!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 32 63 03 00 90 02 30 05 24 9d 3e 00 90 02 30 39 01 90 02 30 0f 90 02 30 83 e9 04 90 02 30 68 94 99 06 00 90 02 30 58 90 02 30 05 b9 66 4c 00 90 02 30 8b 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}