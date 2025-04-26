
rule VirTool_Win32_Obfuscator_AJY{
	meta:
		description = "VirTool:Win32/Obfuscator.AJY,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c6 04 17 41 eb ed 89 fb 89 f7 b9 ?? ?? ?? ?? 31 d2 ac 32 04 13 (42 aa|aa 42) 89 d0 31 d2 bd ?? ?? ?? ?? f7 f5 e2 ed } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}