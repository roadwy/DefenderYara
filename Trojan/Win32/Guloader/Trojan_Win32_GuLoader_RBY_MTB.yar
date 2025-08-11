
rule Trojan_Win32_GuLoader_RBY_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 57 69 74 6e 65 73 73 65 72 73 31 35 33 5c 72 61 61 62 74 65 5c 61 6d 75 6c 65 74 74 65 72 73 } //1 \Witnessers153\raabte\amuletters
		$a_81_1 = {72 65 61 73 6f 6e 69 6e 67 73 20 64 65 6d 6f 72 61 6c 69 73 65 72 20 72 61 64 69 6f 61 6d 70 6c 69 66 69 65 72 } //1 reasonings demoraliser radioamplifier
		$a_81_2 = {63 6f 6d 6d 69 6e 67 6c 65 72 20 64 69 61 6c 79 73 65 73 } //1 commingler dialyses
		$a_81_3 = {73 77 6f 72 64 67 72 61 73 73 } //1 swordgrass
		$a_81_4 = {61 70 70 72 69 7a 61 6c 2e 65 78 65 } //1 apprizal.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}