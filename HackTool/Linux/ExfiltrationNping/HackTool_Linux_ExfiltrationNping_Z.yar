
rule HackTool_Linux_ExfiltrationNping_Z{
	meta:
		description = "HackTool:Linux/ExfiltrationNping.Z,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 00 70 00 69 00 6e 00 67 00 } //10 nping
		$a_00_1 = {20 00 2d 00 63 00 20 00 } //10  -c 
		$a_00_2 = {2d 00 2d 00 64 00 61 00 74 00 61 00 20 00 } //10 --data 
		$a_00_3 = {20 00 2d 00 2d 00 64 00 61 00 74 00 61 00 2d 00 73 00 74 00 72 00 69 00 6e 00 67 00 20 00 } //10  --data-string 
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=30
 
}