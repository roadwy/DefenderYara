
rule VirTool_Win32_CeeInject_BEA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BEA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 ff d0 8b f0 ba 00 a0 00 10 8b ce 2b d6 bf ?? ?? ?? ?? 8b ff 8a 04 0a 34 ?? 88 01 41 83 ef 01 75 f3 8d 4c 24 20 51 ff d6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}