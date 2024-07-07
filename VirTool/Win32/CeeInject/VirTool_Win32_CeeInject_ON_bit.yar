
rule VirTool_Win32_CeeInject_ON_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ON!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 45 ef 8b 0d 90 01 04 03 8d b8 fe ff ff 8b 55 9c 8b 45 d8 8a 14 50 88 11 90 00 } //1
		$a_03_1 = {33 c0 85 c9 a1 c8 90 01 01 41 00 0b fb 2b f9 93 ff d3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}