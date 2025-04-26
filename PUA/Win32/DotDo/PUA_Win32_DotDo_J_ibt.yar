
rule PUA_Win32_DotDo_J_ibt{
	meta:
		description = "PUA:Win32/DotDo.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 28 0f 00 00 0a 0b 16 0c 2b 17 07 08 9a 0a 02 17 58 10 00 02 17 31 06 06 6f 10 00 00 0a 08 17 58 0c 08 07 8e 69 32 e3 } //1
		$a_03_1 = {16 72 01 00 00 70 72 01 00 00 70 28 01 00 00 06 16 72 ?? 00 00 70 72 ?? 00 00 70 28 01 00 00 06 2a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}