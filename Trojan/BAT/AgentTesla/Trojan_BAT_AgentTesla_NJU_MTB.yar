
rule Trojan_BAT_AgentTesla_NJU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 65 35 35 37 33 62 31 65 2d 30 32 63 61 2d 34 31 62 38 2d 62 31 32 66 2d 36 62 62 63 39 61 65 62 30 64 30 34 } //10 $e5573b1e-02ca-41b8-b12f-6bbc9aeb0d04
		$a_01_1 = {4d 61 72 74 69 6e 73 76 69 6c 6c 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 Martinsville.Resources.resource
		$a_01_2 = {57 dd a2 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 } //1
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}