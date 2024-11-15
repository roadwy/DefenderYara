
rule Ransom_Linux_Interlock_A_MTB{
	meta:
		description = "Ransom:Linux/Interlock.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 69 6e 74 65 72 6c 6f 63 6b } //1 .interlock
		$a_01_1 = {2f 21 5f 5f 52 45 41 44 4d 45 5f 5f 21 2e 74 78 74 } //1 /!__README__!.txt
		$a_01_2 = {5f 66 74 72 79 6c 6f 63 6b 66 69 6c 65 } //1 _ftrylockfile
		$a_01_3 = {43 52 49 54 49 43 41 4c 20 53 45 43 55 52 49 54 59 20 41 4c 45 52 54 } //1 CRITICAL SECURITY ALERT
		$a_03_4 = {74 74 70 3a 2f 2f [0-58] 2e 6f 6e 69 6f 6e 2f 73 75 70 70 6f 72 74 2f 73 74 65 70 2e 70 68 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}