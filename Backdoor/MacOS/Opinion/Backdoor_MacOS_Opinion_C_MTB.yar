
rule Backdoor_MacOS_Opinion_C_MTB{
	meta:
		description = "Backdoor:MacOS/Opinion.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 61 63 41 6e 61 6c 79 73 65 72 2f 6d 61 63 61 6e 61 6c 79 73 65 72 2f 4d 4d 50 72 6f 63 65 73 73 49 6e 66 6f 2e 63 70 70 } //1 MacAnalyser/macanalyser/MMProcessInfo.cpp
		$a_00_1 = {73 65 74 53 68 65 6c 6c } //1 setShell
		$a_00_2 = {2f 76 61 72 2f 72 75 6e 2f 4f 53 4d 49 4d 50 51 2e 73 6f 63 6b 65 74 } //1 /var/run/OSMIMPQ.socket
		$a_00_3 = {68 74 74 70 3a 2f 2f 6c 6f 63 61 6c 68 6f 73 74 3a 38 32 35 34 2f 71 72 79 43 68 72 6f 6d 65 50 69 64 2e 70 69 64 3d 25 64 } //1 http://localhost:8254/qryChromePid.pid=%d
		$a_00_4 = {4d 61 63 41 6e 61 6c 79 73 65 72 2f 4f 53 4d 49 4d 48 4b 2f 6f 73 6d 69 6d 68 6b 2f 6d 61 63 68 5f 6f 76 65 72 72 69 64 65 2e 63 } //1 MacAnalyser/OSMIMHK/osmimhk/mach_override.c
		$a_00_5 = {73 77 69 7a 7a 6c 65 73 61 66 61 72 69 } //1 swizzlesafari
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}