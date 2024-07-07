
rule VirTool_Win32_VBInject_BAM_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAM!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 5e 82 12 00 90 02 30 05 f8 7d 2f 00 90 02 30 39 01 0f 85 86 90 02 02 ff 90 02 30 83 e9 04 90 02 30 68 c1 cf 2d 00 90 02 30 58 90 02 30 05 8c 30 25 00 90 02 30 8b 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}