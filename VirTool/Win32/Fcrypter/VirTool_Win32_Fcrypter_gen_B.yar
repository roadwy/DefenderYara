
rule VirTool_Win32_Fcrypter_gen_B{
	meta:
		description = "VirTool:Win32/Fcrypter.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 83 74 0c 03 ?? e2 f9 c3 90 09 10 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 54 68 ?? 00 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}