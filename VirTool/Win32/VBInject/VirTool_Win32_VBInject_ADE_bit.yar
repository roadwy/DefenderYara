
rule VirTool_Win32_VBInject_ADE_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 ff 81 cf 4c 00 53 00 eb 21 90 0a 30 00 8b 00 [0-10] 8b 58 28 } //1
		$a_03_1 = {bb 83 ec 8b 54 [0-30] 43 39 18 75 ?? c1 ee 00 81 78 04 ec 0c 56 8d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}