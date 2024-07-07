
rule VirTool_Win32_Injector_FGT_MTB{
	meta:
		description = "VirTool:Win32/Injector.FGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d0 59 b4 38 4d 87 31 5f 9c f1 0a c5 6b c9 72 38 12 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}