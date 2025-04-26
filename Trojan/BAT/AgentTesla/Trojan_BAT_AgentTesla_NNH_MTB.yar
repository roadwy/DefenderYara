
rule Trojan_BAT_AgentTesla_NNH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {45 66 66 66 66 66 73 64 66 73 64 66 73 64 66 66 66 66 66 66 66 66 73 64 66 73 64 66 66 66 66 66 66 66 66 66 66 66 } //1 Efffffsdfsdfsdffffffffsdfsdfffffffffff
		$a_01_1 = {61 61 61 61 61 61 70 66 73 64 66 64 73 66 6b 70 61 61 67 64 66 67 64 61 61 61 61 61 61 61 61 61 61 61 61 61 } //1 aaaaaapfsdfdsfkpaagdfgdaaaaaaaaaaaaa
		$a_01_2 = {53 46 41 53 47 47 47 47 47 47 47 47 47 47 47 47 47 47 } //1 SFASGGGGGGGGGGGGGG
		$a_01_3 = {6a 66 73 64 64 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 67 73 64 6b } //1 jfsddaaaaaaaaaaaaaaaaaagsdk
		$a_01_4 = {4d 61 73 73 73 73 73 69 6e } //1 Masssssin
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}