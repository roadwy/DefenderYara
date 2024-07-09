
rule VirTool_Win32_VBInject_BAO_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAO!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 53 8b ec 83 [0-30] 5b [0-30] 43 [0-30] 43 [0-30] be 00 10 40 00 [0-30] ad [0-30] 83 f8 00 [0-30] 74 [0-30] 39 18 [0-30] 75 [0-30] 57 [0-30] bf eb 0c 56 8d [0-30] 47 [0-30] 39 78 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}