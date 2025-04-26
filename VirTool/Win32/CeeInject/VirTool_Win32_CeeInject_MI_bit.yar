
rule VirTool_Win32_CeeInject_MI_bit{
	meta:
		description = "VirTool:Win32/CeeInject.MI!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 10 51 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? 00 68 02 00 00 80 ff d6 ff d7 8d 54 ?? ?? a3 ?? ?? ?? 00 52 ff d3 4d 75 d7 } //1
		$a_03_1 = {8a 0c 11 88 0c 38 8b 4d 08 8a 45 0f d3 e3 33 db 8b 4d 08 8a 45 0f d3 e3 33 db 0b 1d ?? ?? ?? 00 03 d9 8a 0b [0-10] 33 c1 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}