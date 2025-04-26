
rule Trojan_BAT_AgentTesla_MBKG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_00_0 = {24 39 61 63 37 32 39 30 34 2d 32 32 66 66 2d 34 32 39 36 2d 38 36 63 39 2d 38 33 34 65 39 30 31 63 39 63 33 31 } //5 $9ac72904-22ff-4296-86c9-834e901c9c31
		$a_00_1 = {54 72 69 76 69 61 4e 6f 77 2e 51 75 65 73 74 69 6f 6e 44 65 74 61 69 6c 73 2e 72 65 73 6f 75 72 63 65 } //5 TriviaNow.QuestionDetails.resource
		$a_01_2 = {48 65 78 53 74 72 69 6e 67 54 6f 42 79 74 65 41 72 72 61 79 } //1 HexStringToByteArray
		$a_01_3 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_4 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}