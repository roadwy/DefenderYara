
rule Trojan_Win32_Guloader_RSA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {72 65 67 6e 73 6b 6f 76 73 5c 75 6e 64 65 72 70 72 6f 67 72 61 6d 6d 65 72 73 } //1 regnskovs\underprogrammers
		$a_81_1 = {5c 6c 73 65 73 76 61 67 65 5c 62 61 6c 65 73 74 72 61 2e 62 69 73 } //1 \lsesvage\balestra.bis
		$a_81_2 = {73 6f 6d 6d 65 72 66 65 72 69 65 72 20 6a 61 63 6b 72 6f 6c 6c 73 } //1 sommerferier jackrolls
		$a_81_3 = {67 72 61 76 65 73 74 6f 6e 65 73 20 64 6f 6d 6f 72 67 61 6e 69 73 74 65 72 20 6f 72 73 69 6e 6f } //1 gravestones domorganister orsino
		$a_81_4 = {6f 76 65 72 70 72 65 73 75 6d 70 74 69 76 65 6e 65 73 73 20 66 69 62 65 72 69 7a 69 6e 67 20 65 74 61 70 65 76 69 73 74 } //1 overpresumptiveness fiberizing etapevist
		$a_81_5 = {73 65 6e 73 61 74 69 6f 6e 73 6c 79 73 74 20 6d 65 6c 61 73 73 69 67 65 6e 69 63 20 63 75 6d 69 6e 6f 6c 65 } //1 sensationslyst melassigenic cuminole
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}