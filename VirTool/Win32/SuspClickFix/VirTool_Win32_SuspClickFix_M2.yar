
rule VirTool_Win32_SuspClickFix_M2{
	meta:
		description = "VirTool:Win32/SuspClickFix.M2,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 00 66 00 69 00 6e 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 [0-20] 40 00 [0-40] 2e 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}