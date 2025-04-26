
rule Trojan_BAT_AgentTesla_NUW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 55 a2 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 75 00 00 00 13 00 00 00 97 00 00 00 90 01 00 00 18 01 00 00 c3 00 00 00 d8 02 00 00 01 } //1
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 52 65 73 6f 75 72 63 65 } //1 WindowsApplication1.Resource
		$a_01_2 = {65 39 65 64 31 61 35 38 30 30 30 33 } //1 e9ed1a580003
		$a_01_3 = {46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}