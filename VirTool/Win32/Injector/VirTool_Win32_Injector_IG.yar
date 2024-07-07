
rule VirTool_Win32_Injector_IG{
	meta:
		description = "VirTool:Win32/Injector.IG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 33 f0 33 fa 89 75 f0 eb } //1
		$a_01_1 = {33 32 35 38 38 37 38 39 24 00 } //1 ㈳㠵㜸㤸$
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}