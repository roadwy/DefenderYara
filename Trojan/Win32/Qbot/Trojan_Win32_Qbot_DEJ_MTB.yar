
rule Trojan_Win32_Qbot_DEJ_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_81_0 = {74 6a 38 75 68 35 6e 74 39 75 79 32 33 67 34 62 38 74 75 79 67 32 33 74 72 79 67 37 79 71 } //1 tj8uh5nt9uy23g4b8tuyg23tryg7yq
		$a_81_1 = {6a 52 6f 59 57 69 6c 71 7a 45 } //1 jRoYWilqzE
		$a_81_2 = {45 6c 66 71 46 62 79 4d 46 72 } //1 ElfqFbyMFr
		$a_81_3 = {49 65 6c 45 45 4e 59 6e 58 4e } //1 IelEENYnXN
		$a_81_4 = {7a 4d 43 4a 71 41 6c 59 41 52 } //1 zMCJqAlYAR
		$a_81_5 = {75 48 4f 4d 71 54 51 78 4d 4a } //1 uHOMqTQxMJ
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=2
 
}