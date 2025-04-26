
rule HackTool_Win32_InvokeInveigh{
	meta:
		description = "HackTool:Win32/InvokeInveigh,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 69 00 6e 00 76 00 65 00 69 00 67 00 68 00 20 00 } //1 invoke-inveigh 
	condition:
		((#a_00_0  & 1)*1) >=1
 
}