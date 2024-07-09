
rule VirTool_Win32_Injector_IA{
	meta:
		description = "VirTool:Win32/Injector.IA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 50 c6 45 ?? 6d c6 45 ?? 79 c6 45 ?? 61 c6 45 ?? 70 c6 45 ?? 70 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}