
rule MonitoringTool_MacOS_EaseMon_K_MTB{
	meta:
		description = "MonitoringTool:MacOS/EaseMon.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 69 6b 6d 2e 6d 61 63 6f 73 2e 75 73 65 72 61 67 65 6e 74 2e 70 6c 69 73 74 } //1 com.ikm.macos.useragent.plist
		$a_00_1 = {55 6e 6c 6f 61 64 20 6b 65 79 73 74 72 6f 6b 65 73 20 6b 65 78 74 } //1 Unload keystrokes kext
		$a_00_2 = {63 6f 6d 2e 65 6d 2e 6d 65 73 73 61 67 65 70 6f 72 74 2e 55 70 64 61 74 65 } //1 com.em.messageport.Update
		$a_00_3 = {2f 4c 69 62 72 61 72 79 2f 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 75 70 70 6f 72 74 2f 69 6b 65 79 6d 6f 6e 69 74 6f 72 2d 73 75 70 70 6f 72 74 2f } //1 /Library/Application Support/ikeymonitor-support/
		$a_00_4 = {73 63 72 65 65 6e 63 61 70 74 75 72 65 20 2d 78 43 20 2d 74 6a 70 67 20 25 40 } //1 screencapture -xC -tjpg %@
		$a_00_5 = {75 70 6c 6f 61 64 53 63 72 65 65 6e 73 68 6f 74 73 } //1 uploadScreenshots
		$a_00_6 = {69 6b 6d 2e 61 77 73 61 70 69 2e 69 6f 2f 69 6e 64 65 78 2e 70 68 70 3f 6d 3d 61 70 69 26 61 3d } //1 ikm.awsapi.io/index.php?m=api&a=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}