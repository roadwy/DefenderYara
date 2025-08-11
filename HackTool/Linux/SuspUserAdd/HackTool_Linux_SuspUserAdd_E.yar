
rule HackTool_Linux_SuspUserAdd_E{
	meta:
		description = "HackTool:Linux/SuspUserAdd.E,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {75 00 73 00 65 00 72 00 61 00 64 00 64 00 } //10 useradd
		$a_00_1 = {61 00 69 00 75 00 73 00 65 00 72 00 } //10 aiuser
		$a_00_2 = {2d 00 4b 00 20 00 4d 00 41 00 49 00 4c 00 5f 00 44 00 49 00 52 00 3d 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 } //10 -K MAIL_DIR=/dev/null
		$a_00_3 = {2d 00 4b 00 20 00 4d 00 41 00 49 00 4c 00 5f 00 46 00 49 00 4c 00 45 00 3d 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 } //10 -K MAIL_FILE=/dev/null
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}