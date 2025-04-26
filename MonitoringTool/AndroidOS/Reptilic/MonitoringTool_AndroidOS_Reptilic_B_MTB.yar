
rule MonitoringTool_AndroidOS_Reptilic_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Reptilic.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 63 2f 73 79 73 75 70 64 2f 63 6c 69 65 6e 74 } //1 yc/sysupd/client
		$a_01_1 = {61 6e 64 72 6f 69 64 5f 63 6c 69 65 6e 74 5f 76 65 72 73 69 6f 6e 2e 70 68 70 } //1 android_client_version.php
		$a_01_2 = {46 61 6b 65 41 63 74 69 76 69 74 79 } //1 FakeActivity
		$a_01_3 = {63 6d 56 77 64 47 6c 73 61 57 4e 31 63 79 35 75 5a 58 51 3d } //1 cmVwdGlsaWN1cy5uZXQ=
		$a_01_4 = {72 65 61 64 5f 62 72 6f 77 73 65 72 5f 68 69 73 74 6f 72 79 } //1 read_browser_history
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}