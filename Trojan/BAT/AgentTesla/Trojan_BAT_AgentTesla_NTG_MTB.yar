
rule Trojan_BAT_AgentTesla_NTG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {13 0a 11 0a 20 08 56 4b 12 20 ?? ?? ?? 68 66 61 58 20 ?? ?? ?? 5f 5a 66 25 13 09 1f 0f 5e } //5
		$a_01_1 = {4e 69 73 67 63 6b 65 20 4d 61 6e 6b 61 72 69 6e } //1 Nisgcke Mankarin
		$a_01_2 = {53 63 72 65 65 6e 54 6f 47 69 66 20 41 70 70 6c 69 63 61 74 69 6f 6e } //1 ScreenToGif Application
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_NTG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 d5 02 fc 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 38 00 00 00 10 00 00 00 2f 00 00 00 47 00 00 00 0e 00 00 00 55 00 00 00 0e 00 00 00 01 00 00 00 01 00 00 00 14 00 00 00 02 00 00 00 01 00 00 00 02 00 00 00 01 00 00 00 0a } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_3 = {48 74 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //1 HttpWebResponse
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}