
rule Backdoor_MacOS_Proton_A_MTB{
	meta:
		description = "Backdoor:MacOS/Proton.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 2e 64 69 6f 33 77 65 2f 2e 70 72 65 6c 69 6d 2e 70 6e 67 } //1 /tmp/.dio3we/.prelim.png
		$a_00_1 = {53 79 6d 61 6e 74 65 63 20 4d 61 6c 77 61 72 65 20 44 65 74 65 63 74 6f 72 2f 46 4d 44 61 74 61 62 61 73 65 51 75 65 75 65 2e 6d } //1 Symantec Malware Detector/FMDatabaseQueue.m
		$a_00_2 = {63 6f 6d 2e 53 79 6d 61 6e 74 65 63 2e 73 6d 64 } //1 com.Symantec.smd
		$a_00_3 = {73 79 6d 61 6e 74 65 63 68 65 75 72 65 6e 67 69 6e 65 2e 63 6f 6d } //1 symantecheurengine.com
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}