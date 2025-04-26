
rule TrojanDropper_AndroidOS_LOP_A_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/LOP.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {68 67 75 70 64 61 74 65 2e 68 6d 61 70 69 2e 63 6f 6d } //3 hgupdate.hmapi.com
		$a_00_1 = {6b 69 6c 6c 50 72 6f 63 65 73 73 } //1 killProcess
		$a_00_2 = {70 74 68 72 6b 75 70 2e 64 6f } //1 pthrkup.do
		$a_00_3 = {64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 64 65 78 63 6c 61 73 73 6c 6f 61 64 65 72 } //1 dalvik/system/dexclassloader
		$a_00_4 = {53 79 73 69 6e 73 74 61 6c 6c 41 70 6b } //1 SysinstallApk
		$a_00_5 = {66 75 6e 63 3a 52 65 71 75 65 73 74 49 6e 73 74 61 6c 6c } //1 func:RequestInstall
		$a_00_6 = {53 74 61 72 74 44 77 6f 6e 41 70 6b } //1 StartDwonApk
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}