
rule VirTool_Win32_VBInject_AGM_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGM!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 30 46 5b 31 f3 3b 9c 24 ?? ?? ?? ?? 75 f1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}