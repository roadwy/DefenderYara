
rule HackTool_Linux_Linikatz_C{
	meta:
		description = "HackTool:Linux/Linikatz.C,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_00_0 = {67 00 72 00 65 00 70 00 20 00 2d 00 45 00 20 00 4d 00 41 00 50 00 49 00 7c 00 5c 00 24 00 36 00 5c 00 24 00 } //10 grep -E MAPI|\$6\$
		$a_00_1 = {65 00 67 00 72 00 65 00 70 00 20 00 2d 00 41 00 20 00 31 00 20 00 44 00 4e 00 3d 00 4e 00 41 00 4d 00 45 00 } //10 egrep -A 1 DN=NAME
		$a_00_2 = {65 00 67 00 72 00 65 00 70 00 20 00 6c 00 77 00 73 00 6d 00 64 00 7c 00 6c 00 77 00 2d 00 } //10 egrep lwsmd|lw-
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=10
 
}