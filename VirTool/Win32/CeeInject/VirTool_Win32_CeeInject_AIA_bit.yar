
rule VirTool_Win32_CeeInject_AIA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AIA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b f8 85 db 7e 17 8d 9b 00 00 00 00 e8 bb ff ff ff 30 84 3e 00 fe ff ff 46 3b f3 7c ef 5f } //1
		$a_01_1 = {64 a1 2c 00 00 00 8b 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}