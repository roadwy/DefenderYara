
rule VirTool_Win32_CeeInject_SC_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 37 88 14 1e 83 fe 90 01 01 75 90 01 01 8d 45 f0 50 6a 90 01 01 68 90 01 04 53 ff 15 90 00 } //1
		$a_03_1 = {8b d7 c1 ea 90 01 01 03 55 90 01 01 8b c7 c1 e0 90 01 01 03 45 90 01 01 8d 0c 3b 33 d0 33 d1 2b f2 8b d6 c1 ea 90 01 01 03 55 90 01 01 8b c6 c1 e0 90 01 01 03 45 90 01 01 8d 0c 33 33 d0 33 d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}