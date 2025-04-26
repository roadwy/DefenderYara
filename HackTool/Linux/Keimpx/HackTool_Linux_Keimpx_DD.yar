
rule HackTool_Linux_Keimpx_DD{
	meta:
		description = "HackTool:Linux/Keimpx.DD,SIGNATURE_TYPE_CMDHSTR_EXT,17 00 17 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //1 python
		$a_00_1 = {6b 00 65 00 69 00 6d 00 70 00 78 00 } //20 keimpx
		$a_00_2 = {2d 00 63 00 20 00 } //1 -c 
		$a_00_3 = {2d 00 74 00 20 00 } //1 -t 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*20+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=23
 
}