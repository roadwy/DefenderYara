
rule VirTool_Win32_VBInject_ADA_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 53 8b ec 83 [0-10] 5b [0-10] 43 43 be 00 10 40 00 [0-10] ad [0-10] 83 f8 00 74 [0-10] 39 18 75 [0-10] 81 78 04 ec 0c 56 8d 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}