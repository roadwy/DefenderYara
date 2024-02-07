
rule HackTool_AndroidOS_UsbCleaver_A_MTB{
	meta:
		description = "HackTool:AndroidOS/UsbCleaver.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 73 62 63 6c 65 61 76 65 72 } //01 00  usbcleaver
		$a_00_1 = {55 64 70 66 6c 6f 6f 64 } //01 00  Udpflood
		$a_00_2 = {77 77 77 2e 62 75 67 74 72 61 71 2d 74 65 61 6d 2e 63 6f 6d } //01 00  www.bugtraq-team.com
		$a_02_3 = {63 70 20 2f 73 64 63 61 72 64 2f 44 6f 77 6e 6c 6f 61 64 2f 90 02 10 20 2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 62 75 67 74 72 6f 69 64 2f 90 00 } //01 00 
		$a_00_4 = {63 68 6d 6f 64 20 37 37 37 20 2f 64 61 74 61 2f 64 61 74 61 2f 63 6f 6d 2e 62 75 67 74 72 6f 69 64 2f } //01 00  chmod 777 /data/data/com.bugtroid/
		$a_00_5 = {52 6f 75 74 65 72 20 42 72 75 74 65 20 46 6f 72 63 65 } //00 00  Router Brute Force
	condition:
		any of ($a_*)
 
}