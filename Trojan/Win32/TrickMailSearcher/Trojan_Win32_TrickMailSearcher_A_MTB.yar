
rule Trojan_Win32_TrickMailSearcher_A_MTB{
	meta:
		description = "Trojan:Win32/TrickMailSearcher.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {6d 61 69 6c 46 69 6e 64 65 72 5f 78 90 02 04 2e 64 6c 6c 90 00 } //1
		$a_81_1 = {74 65 73 74 4d 61 69 6c 46 69 6e 64 65 72 } //1 testMailFinder
		$a_81_2 = {54 65 73 74 4d 61 69 6c 46 69 6e 64 65 72 } //1 TestMailFinder
		$a_81_3 = {65 6e 64 20 6f 66 20 55 52 4c 73 } //1 end of URLs
		$a_81_4 = {55 52 4c 20 69 6e 20 73 68 61 72 65 64 20 6d 65 6d 6f 72 79 } //1 URL in shared memory
		$a_81_5 = {45 6e 64 20 6f 66 20 6d 61 69 6c 43 6f 6c 6c 65 63 74 6f 72 } //1 End of mailCollector
		$a_81_6 = {5c 4c 4f 47 5c 6d 61 69 6c 46 69 6e 64 65 72 2e 6c 6f 67 } //1 \LOG\mailFinder.log
		$a_81_7 = {77 61 69 74 69 6e 67 20 63 6f 6d 6d 61 6e 64 20 66 6f 72 20 6d 6f 64 75 6c 65 20 68 61 6e 64 6c 65 20 25 69 } //1 waiting command for module handle %i
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}