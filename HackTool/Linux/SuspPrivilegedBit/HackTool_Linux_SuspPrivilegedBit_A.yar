
rule HackTool_Linux_SuspPrivilegedBit_A{
	meta:
		description = "HackTool:Linux/SuspPrivilegedBit.A,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 00 68 00 6d 00 6f 00 64 00 20 00 } //5 chmod 
		$a_00_1 = {75 00 2b 00 73 00 20 00 } //1 u+s 
		$a_00_2 = {67 00 2b 00 73 00 20 00 } //1 g+s 
		$a_00_3 = {2b 00 73 00 20 00 } //1 +s 
		$a_00_4 = {2b 00 74 00 20 00 } //1 +t 
		$a_02_5 = {63 00 68 00 6d 00 6f 00 64 00 20 00 90 23 01 01 30 90 22 01 03 31 32 34 90 22 03 03 30 2d 37 20 00 } //6
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*6) >=6
 
}