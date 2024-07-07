
rule VirTool_Win32_VBInject_ACR_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACR!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 53 8b ec 83 43 43 39 18 75 90 01 01 bb ea 0c 56 8d 43 43 39 58 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}