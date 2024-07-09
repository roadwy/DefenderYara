
rule VirTool_Win32_CeeInject_OE_bit{
	meta:
		description = "VirTool:Win32/CeeInject.OE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 d8 8b 45 f8 99 8b cf f7 f9 8b ce 89 9c 05 ?? ?? ?? ff 8b 45 f4 99 f7 f9 8a 8c 05 ?? ?? ?? ff 80 f9 3a 8d 84 05 ?? ?? ?? ff 77 04 fe c9 } //1
		$a_03_1 = {ff 45 fc 81 45 08 ?? 00 00 00 db 45 fc 01 7d f8 01 75 f4 dc 1d ?? ?? ?? 00 df e0 9e 72 ?? 68 ?? ?? ?? ?? 8d 85 ?? ?? ?? ff ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}