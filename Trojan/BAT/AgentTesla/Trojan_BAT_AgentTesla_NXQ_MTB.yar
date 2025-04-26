
rule Trojan_BAT_AgentTesla_NXQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 65 61 30 31 64 63 65 37 2d 64 64 37 62 2d 34 32 64 33 2d 62 66 66 66 2d 62 38 65 65 39 66 33 30 34 64 31 39 } //1 $ea01dce7-dd7b-42d3-bfff-b8ee9f304d19
		$a_01_1 = {46 72 69 65 64 6d 61 6e 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 Friedman.Resources.resource
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 6f 6d 70 61 72 65 4f 62 6a 65 63 74 47 72 65 61 74 65 72 45 71 75 61 6c } //1 CompareObjectGreaterEqual
		$a_01_4 = {46 6f 72 4e 65 78 74 43 68 65 63 6b 4f 62 6a } //1 ForNextCheckObj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}