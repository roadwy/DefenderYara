
rule VirTool_Win32_CeeInject_ABF_bit{
	meta:
		description = "VirTool:Win32/CeeInject.ABF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 9c 8b 5c 24 ?? 8b c3 99 b9 47 01 00 00 f7 f9 8b 44 24 ?? 8b cd 8a 04 02 30 04 1f a1 ?? ?? ?? ?? 3b c5 7f 2c } //1
		$a_03_1 = {7f 51 66 81 3d ?? ?? ?? ?? c2 0d 7f 46 66 ff 05 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? 5f 01 00 00 66 03 15 ?? ?? ?? ?? 6a 54 59 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}