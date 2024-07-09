
rule VirTool_Win32_VBInject_AHL_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHL!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb fd fa 0f 10 [0-30] 81 c3 13 15 00 00 [0-30] 31 30 [0-30] 83 c0 04 [0-30] 39 58 fc 75 [0-30] 58 [0-30] ff e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_AHL_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AHL!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 66 73 73 00 ff 0c 24 68 51 72 6f 63 ff 0c 24 68 75 69 6f 6e ff 0c 24 68 70 72 6d 61 ff 0c 24 68 75 49 6e 66 ff 0c 24 68 5b 77 53 65 ff 0c 24 89 e2 e9 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}