
rule Trojan_BAT_AgentTesla_NMA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 31 00 00 0a 2b d5 28 90 01 01 00 00 06 2b d5 6f 90 01 01 00 00 0a 2b d0 28 90 01 01 00 00 0a 2b cb 0b 2b ca 07 2b c9 07 2b c9 28 90 01 01 00 00 0a 90 00 } //5
		$a_01_1 = {50 77 6a 68 68 69 2e 65 78 65 } //1 Pwjhhi.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NMA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 23 00 24 00 40 00 40 00 23 00 24 00 40 00 40 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 73 00 68 00 2f 00 67 00 65 00 74 00 2f 90 01 17 2e 00 74 00 78 00 74 90 00 } //1
		$a_01_1 = {33 00 30 00 33 00 31 00 39 00 5c 00 61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 63 00 6f 00 6d 00 70 00 69 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 } //1
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //1 HttpWebRequest
		$a_01_6 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}