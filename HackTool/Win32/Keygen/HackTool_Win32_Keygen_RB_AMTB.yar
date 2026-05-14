
rule HackTool_Win32_Keygen_RB_AMTB{
	meta:
		description = "HackTool:Win32/Keygen.RB!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 e8 5c 0e 00 00 68 f2 50 40 00 6a 65 ff 75 08 e8 59 0e 00 00 68 e9 03 00 00 ff 35 44 50 40 00 } //1
		$a_01_1 = {50 6a 00 68 80 00 00 00 ff 75 08 e8 2d 0e 00 00 68 b9 50 40 00 ff 75 08 e8 3e 0e 00 00 6a 6a ff 75 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}