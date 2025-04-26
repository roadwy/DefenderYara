
rule Backdoor_AndroidOS_Smsflooder_GV_MTB{
	meta:
		description = "Backdoor:AndroidOS/Smsflooder.GV!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 73 64 63 61 72 64 2f 2e 63 6f 6d 2e 67 61 72 65 6e 61 2e 63 6d 64 6b 2f 63 6d 73 2f 2e 63 61 6c 6c 64 6d 70 2e 74 78 74 } //1 /sdcard/.com.garena.cmdk/cms/.calldmp.txt
		$a_01_1 = {61 64 6d 69 6e 70 61 73 73 6c 6f 63 6b } //1 adminpasslock
		$a_01_2 = {64 6d 70 63 61 6c 6c 6c 6f 67 } //1 dmpcalllog
		$a_01_3 = {64 75 6d 70 73 6d 73 } //1 dumpsms
		$a_01_4 = {55 70 6c 6f 61 64 69 6e 67 20 53 4d 53 20 66 69 6c 65 2e 2e 2e } //1 Uploading SMS file...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}