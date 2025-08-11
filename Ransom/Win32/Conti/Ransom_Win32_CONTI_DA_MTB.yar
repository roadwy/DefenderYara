
rule Ransom_Win32_CONTI_DA_MTB{
	meta:
		description = "Ransom:Win32/CONTI.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 63 75 72 72 65 6e 74 6c 79 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 43 4f 4e 54 49 20 73 74 72 61 69 6e } //1 All of your files are currently encrypted by CONTI strain
		$a_81_1 = {59 4f 55 20 53 48 4f 55 4c 44 20 42 45 20 41 57 41 52 45 21 } //1 YOU SHOULD BE AWARE!
		$a_81_2 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_81_3 = {68 74 74 70 73 3a 2f 2f 63 6f 6e 74 69 72 65 63 6f 76 65 72 79 2e 69 6e 66 6f } //1 https://contirecovery.info
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win32_CONTI_DA_MTB_2{
	meta:
		description = "Ransom:Win32/CONTI.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc7 00 ffffffc7 00 0d 00 00 "
		
	strings :
		$a_81_0 = {64 65 61 74 68 6f 66 72 65 67 } //100 deathofreg
		$a_81_1 = {63 6c 65 61 6e 65 72 5f 2e 6c 6f 67 } //50 cleaner_.log
		$a_81_2 = {44 65 73 74 72 6f 79 69 6e 67 20 62 6f 6f 74 6c 6f 61 64 65 72 } //20 Destroying bootloader
		$a_81_3 = {44 65 73 74 72 6f 79 69 6e 67 20 73 79 73 74 65 6d 20 66 69 6c 65 73 } //20 Destroying system files
		$a_81_4 = {6e 65 74 20 73 74 6f 70 20 77 69 6e 6c 6f 67 6f 6e } //1 net stop winlogon
		$a_81_5 = {6e 65 74 20 73 74 6f 70 20 6c 73 61 73 73 } //1 net stop lsass
		$a_81_6 = {6e 65 74 20 73 74 6f 70 20 73 65 72 76 69 63 65 73 } //1 net stop services
		$a_81_7 = {6e 65 74 20 73 74 6f 70 20 73 70 6f 6f 6c 65 72 } //1 net stop spooler
		$a_81_8 = {6e 65 74 20 73 74 6f 70 20 72 70 63 73 73 } //1 net stop rpcss
		$a_81_9 = {6e 65 74 20 73 74 6f 70 20 57 69 6e 52 45 41 67 65 6e 74 } //1 net stop WinREAgent
		$a_81_10 = {6e 65 74 20 73 74 6f 70 20 52 65 63 6f 76 65 72 79 41 67 65 6e 74 } //1 net stop RecoveryAgent
		$a_81_11 = {6e 65 74 20 73 74 6f 70 20 52 65 63 6f 76 65 72 79 53 65 72 76 69 63 65 } //1 net stop RecoveryService
		$a_81_12 = {6e 65 74 20 73 74 6f 70 20 77 69 6e 69 6e 69 74 } //1 net stop wininit
	condition:
		((#a_81_0  & 1)*100+(#a_81_1  & 1)*50+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=199
 
}