
rule Trojan_Win64_Merlin_A_dha{
	meta:
		description = "Trojan:Win64/Merlin.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 65 72 6c 69 6e } //1 merlin
		$a_01_1 = {70 61 72 72 6f 74 } //1 parrot
		$a_01_2 = {41 67 65 6e 74 3a 20 25 73 } //1 Agent: %s
		$a_01_3 = {73 6b 65 77 } //1 skew
		$a_01_4 = {4b 69 6c 6c 44 61 74 65 } //1 KillDate
		$a_01_5 = {50 6c 61 74 66 6f 72 6d } //1 Platform
		$a_01_6 = {57 61 69 74 54 69 6d 65 } //1 WaitTime
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}