
rule VirTool_Win32_VBInject_ADH_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADH!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 96 89 32 00 [0-30] 05 c0 76 0f 00 [0-30] 39 01 [0-30] 0f [0-30] 83 e9 04 [0-30] 68 77 cc 2f 00 [0-30] 58 [0-30] 05 d6 33 23 00 [0-30] 8b 09 [0-30] 39 c1 [0-30] 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}