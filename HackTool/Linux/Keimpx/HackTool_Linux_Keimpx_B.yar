
rule HackTool_Linux_Keimpx_B{
	meta:
		description = "HackTool:Linux/Keimpx.B,SIGNATURE_TYPE_CMDHSTR_EXT,17 00 17 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //1 python
		$a_00_1 = {6b 00 65 00 69 00 6d 00 70 00 78 00 } //20 keimpx
		$a_00_2 = {2d 00 2d 00 6c 00 6d 00 3d 00 } //1 --lm=
		$a_00_3 = {2d 00 2d 00 6e 00 74 00 3d 00 } //1 --nt=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*20+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=23
 
}