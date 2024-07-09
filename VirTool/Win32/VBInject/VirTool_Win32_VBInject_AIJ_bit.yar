
rule VirTool_Win32_VBInject_AIJ_bit{
	meta:
		description = "VirTool:Win32/VBInject.AIJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 10 4c 23 00 [0-30] 05 46 b4 1e 00 [0-30] 39 01 [0-30] 0f [0-30] 83 e9 04 [0-30] 68 77 c1 21 00 [0-30] 58 [0-30] 05 d6 3e 31 00 [0-30] 8b 09 [0-30] 39 c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}