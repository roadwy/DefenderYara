
rule VirTool_Win32_Obfuscator_QM{
	meta:
		description = "VirTool:Win32/Obfuscator.QM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ac 2a c2 fe c8 c0 c0 03 fe c8 2a c2 c0 c0 02 32 c2 d0 c8 02 c2 2c ?? fe c0 c0 c8 04 04 ?? c0 c0 02 fe c0 2c ?? 32 c2 d0 c8 2c ?? 32 c2 aa c1 c2 08 e2 cd 8f 44 24 1c 61 ff e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}