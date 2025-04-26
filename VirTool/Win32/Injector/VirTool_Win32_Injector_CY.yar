
rule VirTool_Win32_Injector_CY{
	meta:
		description = "VirTool:Win32/Injector.CY,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 8b 8c e4 d1 56 8b d8 e8 ?? ?? ?? ?? 68 6b 43 15 20 56 89 45 68 e8 ?? ?? ?? ?? 68 ea 56 5c b8 56 89 45 5c e8 ?? ?? ?? ?? 68 6a 34 4f a2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}