
rule MonitoringTool_MacOS_Easemon_A_MTB{
	meta:
		description = "MonitoringTool:MacOS/Easemon.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {65 61 73 65 6d 6f 6e } //1 easemon
		$a_00_1 = {63 6f 6d 2e 61 62 2e 65 6d 2e 75 70 64 61 74 65 2e 70 6c 69 73 74 } //1 com.ab.em.update.plist
		$a_00_2 = {63 63 63 37 30 37 64 32 39 32 34 37 36 38 66 32 63 63 31 32 62 63 38 62 } //1 ccc707d2924768f2cc12bc8b
		$a_00_3 = {63 68 66 6c 61 67 73 20 2d 52 20 68 69 64 64 65 6e } //1 chflags -R hidden
		$a_00_4 = {64 73 63 6c 20 2e 20 2d 6c 73 20 2f 55 73 65 72 73 20 68 6f 6d 65 20 7c 20 67 72 65 70 20 2d 69 20 2f 55 73 65 72 } //1 dscl . -ls /Users home | grep -i /User
		$a_00_5 = {75 70 6c 6f 61 64 57 65 62 48 69 73 74 6f 72 79 } //1 uploadWebHistory
		$a_00_6 = {69 6b 6d 2e 61 77 73 61 70 69 2e 69 6f 2f 69 6e 64 65 78 2e 70 68 70 3f 6d 3d 61 70 69 26 61 3d } //1 ikm.awsapi.io/index.php?m=api&a=
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}