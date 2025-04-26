
rule HackTool_MacOS_SuspiousDataCollect_Z{
	meta:
		description = "HackTool:MacOS/SuspiousDataCollect.Z,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 63 00 72 00 6f 00 6e 00 74 00 61 00 62 00 20 00 2d 00 6c 00 } //10 _bs >/dev/null ; crontab -l
		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 63 00 61 00 74 00 20 00 2f 00 65 00 74 00 63 00 2f 00 73 00 75 00 64 00 6f 00 65 00 72 00 73 00 } //10 _bs >/dev/null ; cat /etc/sudoers
		$a_00_2 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 6e 00 65 00 74 00 73 00 74 00 61 00 74 00 20 00 61 00 6e 00 6f 00 70 00 } //10 _bs >/dev/null ; netstat anop
		$a_00_3 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 77 00 68 00 6f 00 20 00 2d 00 61 00 } //10 _bs >/dev/null ; who -a
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=10
 
}