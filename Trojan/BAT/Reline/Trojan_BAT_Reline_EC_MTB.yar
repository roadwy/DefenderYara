
rule Trojan_BAT_Reline_EC_MTB{
	meta:
		description = "Trojan:BAT/Reline.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {70 69 6d 65 72 2e 62 62 62 63 6f 6e 74 65 6e 74 73 37 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 pimer.bbbcontents7.My.Resources
		$a_81_1 = {70 69 6d 65 72 2e 62 62 62 63 6f 6e 74 65 6e 74 73 37 2e 70 64 62 } //1 pimer.bbbcontents7.pdb
		$a_81_2 = {61 42 56 49 6e 35 6d 55 49 59 4b 34 45 59 72 68 48 64 } //1 aBVIn5mUIYK4EYrhHd
		$a_81_3 = {54 61 73 6b 53 63 68 65 64 75 6c 65 72 52 65 73 75 6d 65 57 69 74 68 41 77 61 69 74 61 62 6c 65 } //1 TaskSchedulerResumeWithAwaitable
		$a_81_4 = {54 61 73 6b 52 65 73 75 6d 65 57 69 74 68 41 77 61 69 74 61 62 6c 65 } //1 TaskResumeWithAwaitable
		$a_81_5 = {54 61 73 6b 41 77 61 69 74 65 72 57 69 74 68 4f 70 74 69 6f 6e 73 } //1 TaskAwaiterWithOptions
		$a_81_6 = {54 61 73 6b 53 63 68 65 64 75 6c 65 72 41 77 61 69 74 65 72 } //1 TaskSchedulerAwaiter
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}