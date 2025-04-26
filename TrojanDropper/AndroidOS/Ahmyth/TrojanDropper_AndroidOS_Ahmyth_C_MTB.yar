
rule TrojanDropper_AndroidOS_Ahmyth_C_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Ahmyth.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 2e 53 79 73 74 65 6d 2f 41 50 4b 2f } //2 /.System/APK/
		$a_00_1 = {73 68 65 6c 6c 5f 65 78 65 63 } //1 shell_exec
		$a_00_2 = {65 78 65 63 75 74 65 4e 61 74 69 76 65 43 6f 64 65 } //1 executeNativeCode
		$a_00_3 = {69 73 50 61 63 6b 61 67 65 49 6e 73 74 61 6c 6c 65 64 } //1 isPackageInstalled
		$a_00_4 = {69 6e 73 74 61 6c 6c 41 50 4b } //1 installAPK
		$a_00_5 = {64 6f 5f 72 6f 6f 74 } //1 do_root
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}