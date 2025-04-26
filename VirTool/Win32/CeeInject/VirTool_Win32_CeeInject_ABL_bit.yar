
rule VirTool_Win32_CeeInject_ABL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 ?? 8a 00 88 45 ?? 8a 45 ?? 34 80 8b 55 08 03 55 ?? 88 02 ff 45 ?? 81 7d f4 ?? ?? ?? ?? 75 dc } //1
		$a_03_1 = {b9 5c 00 00 00 33 d2 f7 f1 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 88 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}