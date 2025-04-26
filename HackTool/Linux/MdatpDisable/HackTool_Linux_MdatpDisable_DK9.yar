
rule HackTool_Linux_MdatpDisable_DK9{
	meta:
		description = "HackTool:Linux/MdatpDisable.DK9,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_00_0 = {6b 00 69 00 6c 00 6c 00 61 00 6c 00 6c 00 20 00 77 00 64 00 61 00 76 00 64 00 61 00 65 00 6d 00 6f 00 6e 00 } //10 killall wdavdaemon
		$a_00_1 = {6b 00 69 00 6c 00 6c 00 61 00 6c 00 6c 00 20 00 74 00 65 00 6c 00 65 00 6d 00 65 00 74 00 72 00 79 00 64 00 5f 00 76 00 32 00 } //10 killall telemetryd_v2
		$a_00_2 = {73 00 79 00 73 00 74 00 65 00 6d 00 63 00 74 00 6c 00 20 00 73 00 74 00 6f 00 70 00 20 00 6d 00 64 00 61 00 74 00 70 00 } //10 systemctl stop mdatp
		$a_00_3 = {73 00 79 00 73 00 74 00 65 00 6d 00 63 00 74 00 6c 00 20 00 73 00 74 00 6f 00 70 00 20 00 6d 00 64 00 65 00 5f 00 6e 00 65 00 74 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //10 systemctl stop mde_netfilter
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=30
 
}