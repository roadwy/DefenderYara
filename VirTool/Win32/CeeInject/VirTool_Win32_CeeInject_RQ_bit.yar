
rule VirTool_Win32_CeeInject_RQ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 0d 6a 21 8b 55 e4 83 c2 28 ff d2 83 c4 04 e9 ?? ?? ?? ff } //1
		$a_03_1 = {6a 40 68 00 30 00 00 68 c5 3e 00 00 6a 00 ff 15 c8 00 01 02 89 45 e4 c7 45 f0 00 00 00 00 8a 95 ?? ?? ?? ff 88 95 ?? ?? ?? ff 8b 8d ?? ?? ?? ff [0-30] 8a 94 05 ?? ?? ?? ff 33 ca [0-20] 8b 55 e4 88 0c 02 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}