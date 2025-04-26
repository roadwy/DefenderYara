
rule HackTool_Linux_PTHToolkitGen_WW{
	meta:
		description = "HackTool:Linux/PTHToolkitGen.WW,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 00 6d 00 62 00 68 00 61 00 73 00 68 00 } //10 smbhash
		$a_00_1 = {2f 00 2f 00 } //5 //
		$a_00_2 = {2d 00 75 00 } //1 -u
		$a_00_3 = {2d 00 61 00 } //1 -a
		$a_00_4 = {2d 00 72 00 75 00 6e 00 61 00 73 00 } //1 -runas
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=16
 
}