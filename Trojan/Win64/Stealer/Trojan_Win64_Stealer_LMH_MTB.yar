
rule Trojan_Win64_Stealer_LMH_MTB{
	meta:
		description = "Trojan:Win64/Stealer.LMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 65 74 61 69 6c 65 64 20 63 72 65 64 65 6e 74 69 61 6c 20 74 65 6c 65 6d 65 74 72 79 20 66 6f 72 20 2a 2a } //20 Detailed credential telemetry for **
		$a_81_1 = {48 61 69 64 65 7a 20 47 72 61 62 62 65 72 } //10 Haidez Grabber
		$a_81_2 = {42 75 67 20 48 75 6e 74 65 72 20 4c 31 } //5 Bug Hunter L1
		$a_81_3 = {42 75 67 20 48 75 6e 74 65 72 20 4c 32 } //4 Bug Hunter L2
		$a_81_4 = {44 65 76 65 6c 6f 70 65 64 20 62 79 20 5a 36 31 64 64 } //3 Developed by Z61dd
		$a_81_5 = {54 65 72 6d 69 6e 61 74 69 6f 6e 20 73 77 65 65 70 20 63 6f 6d 70 6c 65 74 65 2e 20 57 61 69 74 69 6e 67 20 66 6f 72 20 66 69 6c 65 20 6c 6f 63 6b 73 20 74 6f 20 66 75 6c 6c 79 20 72 65 6c 65 61 73 65 2e } //2 Termination sweep complete. Waiting for file locks to fully release.
		$a_81_6 = {53 63 61 6e 6e 69 6e 67 20 66 6f 72 20 61 6e 64 20 74 65 72 6d 69 6e 61 74 69 6e 67 20 62 72 6f 77 73 65 72 20 6e 65 74 77 6f 72 6b 20 73 65 72 76 69 63 65 73 2e 2e 2e } //1 Scanning for and terminating browser network services...
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5+(#a_81_3  & 1)*4+(#a_81_4  & 1)*3+(#a_81_5  & 1)*2+(#a_81_6  & 1)*1) >=45
 
}