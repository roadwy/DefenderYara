
rule VirTool_Win32_VBInject_AGW_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGW!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 f6 e7 1e 00 [0-10] 05 60 18 23 00 [0-10] 39 41 04 [0-10] 68 8d a3 3d 00 [0-10] 05 c0 5c 15 00 [0-10] 39 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}