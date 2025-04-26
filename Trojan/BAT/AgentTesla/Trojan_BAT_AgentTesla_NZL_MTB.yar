
rule Trojan_BAT_AgentTesla_NZL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 fe 0e 16 00 fe 0c 12 00 fe 0c 12 00 59 fe 0c 16 00 61 fe 0c 12 00 58 fe 0e 15 00 fe 0c 11 00 fe 0c 11 00 20 0b } //1
		$a_01_1 = {53 55 63 36 39 54 4e 57 55 4f 6e 5a 42 52 61 51 71 51 2e 6b 63 70 49 59 52 5a 49 30 42 36 57 39 75 49 66 53 77 } //1 SUc69TNWUOnZBRaQqQ.kcpIYRZI0B6W9uIfSw
		$a_01_2 = {52 6b 4d 52 6a 4a 5a 49 5a 5a 72 57 42 61 39 57 56 52 64 00 50 51 62 5a } //1 歒前䩪䥚婚坲慂圹剖d児婢
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_NZL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 97 a2 0b 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 90 00 00 00 20 00 00 00 80 00 00 00 16 01 00 00 9f } //10
		$a_81_1 = {58 43 58 43 58 43 58 43 58 43 58 43 43 58 43 58 58 } //1 XCXCXCXCXCXCCXCXX
		$a_81_2 = {46 46 4b 46 46 4b 46 46 4b } //1 FFKFFKFFK
		$a_81_3 = {58 43 58 43 58 43 58 43 58 43 58 43 58 43 58 43 58 43 43 } //1 XCXCXCXCXCXCXCXCXCC
		$a_81_4 = {58 43 58 43 58 43 58 43 58 43 58 43 58 43 } //1 XCXCXCXCXCXCXC
		$a_81_5 = {73 65 74 5f 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 } //1 set_AAAAAAAAAAAAAAAAAAAAA
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=16
 
}