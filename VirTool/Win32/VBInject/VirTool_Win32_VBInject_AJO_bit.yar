
rule VirTool_Win32_VBInject_AJO_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJO!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 00 10 40 00 [0-10] ad [0-10] bb 57 8b ec 83 [0-10] 4b 4b [0-10] 39 18 75 ?? 39 f0 81 78 04 ec 0c 56 8d 75 dc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}