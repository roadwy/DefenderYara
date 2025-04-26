
rule HackTool_Win32_Keygen_DM_MTB{
	meta:
		description = "HackTool:Win32/Keygen.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {48 53 4b 65 79 67 65 6e } //HSKeygen  1
		$a_80_1 = {48 69 67 68 2d 53 6f 63 69 65 74 79 20 4b 65 79 67 65 6e } //High-Society Keygen  1
		$a_80_2 = {25 4d 65 73 27 61 67 50 42 6f 78 41 } //%Mes'agPBoxA  1
		$a_80_3 = {75 6d 20 6f 6e 37 69 6d 6d } //um on7imm  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}