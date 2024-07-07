
rule Trojan_BAT_AgentTesla_ZN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {03 11 04 18 90 01 05 28 90 01 04 28 90 01 04 04 07 90 01 05 28 90 01 04 6a 61 b7 28 90 00 } //10
		$a_80_1 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //ISectionEntry  1
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  1
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  1
		$a_80_4 = {67 65 74 5f 43 68 61 72 73 } //get_Chars  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=14
 
}