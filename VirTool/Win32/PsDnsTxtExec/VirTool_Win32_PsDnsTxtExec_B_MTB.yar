
rule VirTool_Win32_PsDnsTxtExec_B_MTB{
	meta:
		description = "VirTool:Win32/PsDnsTxtExec.B!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 90 02 10 28 00 6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 90 02 08 20 00 2d 00 71 00 3d 00 74 00 78 00 74 00 20 00 90 02 40 29 00 5b 00 2d 00 31 00 5d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}