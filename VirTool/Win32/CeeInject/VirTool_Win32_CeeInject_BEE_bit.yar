
rule VirTool_Win32_CeeInject_BEE_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BEE!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 68 90 01 04 6a 00 ff d0 be 90 01 02 00 10 8b c8 2b f0 bf a1 05 00 00 5b 8d 64 24 00 8a 14 0e 80 f2 90 01 01 88 11 41 4f 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}