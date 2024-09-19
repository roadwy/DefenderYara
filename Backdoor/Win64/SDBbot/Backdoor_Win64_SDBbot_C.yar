
rule Backdoor_Win64_SDBbot_C{
	meta:
		description = "Backdoor:Win64/SDBbot.C,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 65 73 6f 75 72 63 65 20 7b 7d 20 69 73 20 75 6e 61 76 61 69 6c 61 62 6c 65 } //1 Resource {} is unavailable
		$a_01_1 = {43 6f 75 6c 64 20 6e 6f 74 20 66 69 6e 64 20 72 65 73 6f 75 72 63 65 } //1 Could not find resource
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 63 6f 6d 6d 69 74 20 74 72 61 6e 73 61 63 74 69 6f 6e } //1 Failed to commit transaction
		$a_01_3 = {72 65 73 6f 75 72 63 65 20 64 65 61 64 6c 6f 63 6b 20 77 6f 75 6c 64 20 6f 63 63 75 72 } //1 resource deadlock would occur
		$a_01_4 = {6e 65 74 77 6f 72 6b 20 75 6e 72 65 61 63 68 61 62 6c 65 } //1 network unreachable
		$a_01_5 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 61 6c 72 65 61 64 79 20 69 6e 20 70 72 6f 67 72 65 73 73 } //1 connection already in progress
		$a_01_6 = {74 6f 6f 20 6d 61 6e 79 20 66 69 6c 65 73 20 6f 70 65 6e 20 69 6e 20 73 79 73 74 65 6d } //1 too many files open in system
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}