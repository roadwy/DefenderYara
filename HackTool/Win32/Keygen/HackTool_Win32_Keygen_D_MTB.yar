
rule HackTool_Win32_Keygen_D_MTB{
	meta:
		description = "HackTool:Win32/Keygen.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {47 65 6e 65 72 61 74 65 } //1 Generate
		$a_81_1 = {2d 7c 7c 20 4b 65 79 67 65 6e 20 62 79 20 41 58 69 53 5e 46 69 47 48 54 69 4e 47 20 46 4f 52 20 46 55 4e } //1 -|| Keygen by AXiS^FiGHTiNG FOR FUN
		$a_81_2 = {66 6f 72 20 64 72 65 61 6d 68 61 63 6b 30 31 } //1 for dreamhack01
		$a_81_3 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //1 GetStartupInfoA
		$a_81_4 = {47 65 74 43 50 49 6e 66 6f } //1 GetCPInfo
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}