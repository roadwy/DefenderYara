
rule MonitoringTool_AndroidOS_Sakezon_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Sakezon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 6c 6f 6e 2e 73 6b 7a 2e 53 61 66 65 4b 69 64 5a 6f 6e 65 } //1 slon.skz.SafeKidZone
		$a_01_1 = {6c 6f 67 69 6e 2e 73 61 66 65 6b 69 64 7a 6f 6e 65 2e 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 75 70 6c 6f 61 64 2e 70 68 70 } //1 login.safekidzone.com/android/upload.php
		$a_01_2 = {2e 63 6f 6d 2f 70 68 70 2f 73 65 73 73 69 6f 6e 2e 70 68 70 } //1 .com/php/session.php
		$a_01_3 = {2e 63 6f 6d 2f 6c 69 73 74 65 6e 65 72 2e 70 68 70 } //1 .com/listener.php
		$a_01_4 = {47 70 73 50 6c 75 73 53 65 72 76 69 63 65 } //1 GpsPlusService
		$a_01_5 = {73 61 66 65 74 72 65 63 } //1 safetrec
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}