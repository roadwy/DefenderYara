
rule HackTool_MacOS_SuspSysDataCollect_EH1{
	meta:
		description = "HackTool:MacOS/SuspSysDataCollect.EH1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 66 00 69 00 6e 00 64 00 2d 00 63 00 65 00 72 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 65 00 20 00 2d 00 61 00 20 00 2d 00 70 00 20 00 3e 00 20 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 } //10 _bs >/dev/null ; security find-certificate -a -p > /dev/null
		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 66 00 69 00 6c 00 65 00 20 00 2f 00 62 00 69 00 6e 00 2f 00 70 00 77 00 64 00 } //10 _bs >/dev/null ; file /bin/pwd
		$a_00_2 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 63 00 61 00 74 00 20 00 2f 00 65 00 74 00 63 00 2f 00 72 00 65 00 73 00 6f 00 6c 00 76 00 2e 00 63 00 6f 00 6e 00 66 00 } //10 _bs >/dev/null ; cat /etc/resolv.conf
		$a_00_3 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 69 00 6f 00 72 00 65 00 67 00 } //10 _bs >/dev/null ; ioreg
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=10
 
}