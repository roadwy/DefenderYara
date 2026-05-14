
rule Trojan_Win64_Diztakun_MX_MTB{
	meta:
		description = "Trojan:Win64/Diztakun.MX!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6f 73 61 6d 61 62 69 6e 6c 61 64 65 6e 63 6c 69 65 6e 74 } //1 osamabinladenclient
		$a_01_1 = {73 74 61 72 74 75 70 2f 61 63 74 69 6f 6e 73 2e 64 65 6c 65 74 65 62 61 63 6b 75 70 73 } //1 startup/actions.deletebackups
		$a_01_2 = {61 64 64 45 78 63 6c 75 73 69 6f 6e 73 } //1 addExclusions
		$a_01_3 = {61 63 74 69 6f 6e 73 2e 64 69 73 61 62 6c 65 52 65 63 6f 76 65 72 79 } //1 actions.disableRecovery
		$a_01_4 = {61 63 74 69 6f 6e 73 2e 50 65 72 73 69 73 74 56 62 73 } //1 actions.PersistVbs
		$a_01_5 = {61 63 74 69 6f 6e 73 2e 64 69 73 61 62 6c 65 55 41 43 } //1 actions.disableUAC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}