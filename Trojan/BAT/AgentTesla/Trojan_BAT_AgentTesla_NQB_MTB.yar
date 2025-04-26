
rule Trojan_BAT_AgentTesla_NQB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 28 ?? ?? ?? 06 07 28 ?? ?? ?? 06 61 d1 9d 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 e1 } //1
		$a_01_1 = {72 65 66 61 63 74 6f 72 } //1 refactor
		$a_81_2 = {73 74 75 64 79 2e 73 74 75 64 79 } //1 study.study
		$a_01_3 = {01 25 16 1f 40 9d 6f } //1
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_7 = {73 70 6c 69 74 74 65 72 } //1 splitter
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}