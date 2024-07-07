
rule HackTool_Win32_Bombim_B_bit{
	meta:
		description = "HackTool:Win32/Bombim.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {d7 d4 b6 af ba e4 d5 a8 } //1
		$a_01_1 = {c8 ab d7 d4 b6 af 51 51 cf fb cf a2 ba e4 d5 a8 bb fa 56 31 2e 31 00 } //1
		$a_01_2 = {ba e4 d5 a8 b5 c4 c4 da c8 dd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}