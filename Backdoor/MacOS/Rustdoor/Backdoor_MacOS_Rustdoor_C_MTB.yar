
rule Backdoor_MacOS_Rustdoor_C_MTB{
	meta:
		description = "Backdoor:MacOS/Rustdoor.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 6d 61 6e 64 74 61 73 6b 6b 69 6c 6c 64 6f 77 6e 6c 6f 61 64 } //1 commandtaskkilldownload
		$a_00_1 = {62 6f 74 6b 69 6c 6c 70 61 72 61 6d } //1 botkillparam
		$a_00_2 = {75 70 6c 6f 61 64 5f 66 69 6c 65 73 72 63 2f 7a 69 70 66 69 6c 65 } //1 upload_filesrc/zipfile
		$a_00_3 = {6c 69 62 2e 72 73 6c 61 75 6e 63 68 63 74 6c 75 6e 6c 6f 61 64 2d 77 46 61 69 6c 65 64 } //1 lib.rslaunchctlunload-wFailed
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}