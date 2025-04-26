
rule VirTool_Win32_Ceeinject_TC_bit{
	meta:
		description = "VirTool:Win32/Ceeinject.TC!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {99 f7 ff 80 c2 30 33 c0 8a c1 88 14 06 8b c3 bb ?? ?? ?? ?? 99 f7 fb 8b d8 49 85 db 90 09 07 00 8b c3 bf } //1
		$a_03_1 = {6a 04 68 00 10 00 00 8b 45 00 2b 06 50 8b 06 50 e8 ?? ?? ?? ?? 85 c0 75 06 33 c0 89 03 } //1
		$a_03_2 = {8b d7 8b 0d ?? ?? ?? ?? 32 54 19 ff f6 d2 88 54 18 ff 43 4e 75 e3 90 09 07 00 8b c5 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}