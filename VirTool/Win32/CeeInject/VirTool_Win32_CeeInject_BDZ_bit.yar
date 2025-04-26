
rule VirTool_Win32_CeeInject_BDZ_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 57 56 51 ff 4d 08 8b 4d 0c 03 c8 83 f8 00 72 14 83 f9 0a 76 0f 83 7d 08 00 76 09 50 ff 75 08 e8 d9 ff ff ff 3b c8 75 10 83 7d 08 00 76 0a 6a 64 ff 75 08 e8 c5 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}