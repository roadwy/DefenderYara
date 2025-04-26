
rule VirTool_Win32_VBInject_BAE_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAE!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 52 c5 21 00 [0-20] 05 04 3b 20 00 [0-20] 39 01 0f 85 29 ff ff ff [0-20] 83 e9 04 [0-20] 68 37 53 43 00 [0-20] 58 [0-20] 05 16 ad 0f 00 [0-20] 8b 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}