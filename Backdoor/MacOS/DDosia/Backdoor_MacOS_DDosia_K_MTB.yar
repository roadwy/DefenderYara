
rule Backdoor_MacOS_DDosia_K_MTB{
	meta:
		description = "Backdoor:MacOS/DDosia.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {64 74 72 61 63 65 73 65 6d 61 63 71 75 69 72 65 64 65 62 75 67 } //1 dtracesemacquiredebug
		$a_00_1 = {68 65 61 70 20 64 75 6d 70 61 73 79 6e 63 70 72 65 65 6d 70 74 6f 66 66 66 6f 72 63 65 } //1 heap dumpasyncpreemptoffforce
		$a_00_2 = {50 6f 69 6e 74 65 72 6d 69 6d 65 2f 6d 75 6c 74 69 70 61 72 74 77 72 69 74 65 20 } //1 Pointermime/multipartwrite 
		$a_00_3 = {48 61 6e 4c 61 6f 4d 72 6f 4e 6b 6f 56 61 69 75 64 70 54 43 50 55 44 50 } //1 HanLaoMroNkoVaiudpTCPUDP
		$a_00_4 = {63 61 6c 6c 47 4f 4d 45 4d 4c 49 4d 49 54 42 61 64 20 76 61 72 69 6e 74 61 74 6f 6d 69 63 } //1 callGOMEMLIMITBad varintatomic
		$a_00_5 = {30 61 74 6f 6d 69 63 6f 72 38 74 72 61 63 65 62 61 63 6b 72 77 78 72 77 78 72 77 78 63 6f 6d 70 6c 65 78 36 34 6d 61 74 68 } //1 0atomicor8tracebackrwxrwxrwxcomplex64math
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}