
rule VirTool_Win32_Dllhij_B{
	meta:
		description = "VirTool:Win32/Dllhij.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 68 01 00 00 00 b8 4d 3c 2b 1a ff d0 } //1
		$a_01_1 = {56 57 89 c7 81 c6 62 04 00 00 b9 0d 00 00 00 f3 a4 5f 5e 8b 8d dc fd ff ff 89 48 07 8b 85 d8 fd ff ff 31 c9 66 8b 08 8b 45 08 29 c8 89 85 d0 fd ff ff 89 8d d4 fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}