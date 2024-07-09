
rule VirTool_Win32_CeeInject_LQ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.LQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 32 59 f8 83 da ?? f7 d1 f8 83 d1 ?? d1 c1 c1 c9 09 01 f1 83 e9 01 51 5e c1 c6 09 d1 ce 51 8f 07 f8 83 d7 04 f8 83 d0 04 3d ?? ?? ?? ?? 75 d0 } //1
		$a_03_1 = {ff 25 98 6d 46 00 90 09 13 00 5f 8b 35 ?? ?? ?? ?? 56 68 7d 4b 46 00 89 3d 98 6d 46 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}