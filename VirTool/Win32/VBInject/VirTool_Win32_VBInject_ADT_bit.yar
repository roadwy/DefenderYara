
rule VirTool_Win32_VBInject_ADT_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADT!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fc ff ff ff 5e 8b 7c 24 08 57 b9 00 08 00 00 f3 a5 bb 90 01 04 5f 31 c9 31 d2 81 f2 00 19 00 00 31 1c 0f 29 c1 29 ca 7d ef ff e7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}