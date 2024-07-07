
rule HackTool_Linux_Keimpx_A{
	meta:
		description = "HackTool:Linux/Keimpx.A,SIGNATURE_TYPE_CMDHSTR_EXT,18 00 18 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //1 python
		$a_00_1 = {6b 00 65 00 69 00 6d 00 70 00 78 00 } //20 keimpx
		$a_00_2 = {2d 00 75 00 20 00 } //1 -u 
		$a_00_3 = {2d 00 70 00 20 00 } //1 -p 
		$a_00_4 = {2d 00 74 00 20 00 } //1 -t 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*20+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=24
 
}