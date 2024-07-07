
rule VirTool_Win32_CeeInject_RA_bit{
	meta:
		description = "VirTool:Win32/CeeInject.RA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {30 07 47 0f af c1 ba 90 01 04 ff 4d 0c 03 c2 40 83 7d 0c 00 77 90 00 } //1
		$a_03_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 1c 8b 50 08 8b 48 20 8b 00 81 79 0c 90 01 04 75 ef 90 00 } //1
		$a_03_2 = {8a c8 c0 f9 90 01 01 80 e1 90 01 01 c0 e2 90 01 01 c0 e0 90 01 01 02 45 90 01 01 32 ca 4e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}