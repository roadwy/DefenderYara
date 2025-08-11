
rule Virus_Win32_Wanex_EH_MTB{
	meta:
		description = "Virus:Win32/Wanex.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {54 68 65 20 4c 61 73 74 20 47 6f 6f 64 62 79 65 } //1 The Last Goodbye
		$a_81_1 = {4d 79 44 6f 6f 6d 20 69 6e 66 65 63 74 65 64 } //1 MyDoom infected
		$a_81_2 = {50 65 77 6b 42 6f 74 } //1 PewkBot
		$a_81_3 = {43 6f 6d 70 75 74 65 72 73 20 49 6e 66 65 63 74 65 64 } //1 Computers Infected
		$a_81_4 = {46 69 6c 65 73 20 49 6e 66 65 63 74 65 64 } //1 Files Infected
		$a_81_5 = {59 6f 75 5f 61 72 65 5f 61 5f 77 61 6e 6b 65 72 2e 65 78 65 } //1 You_are_a_wanker.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}