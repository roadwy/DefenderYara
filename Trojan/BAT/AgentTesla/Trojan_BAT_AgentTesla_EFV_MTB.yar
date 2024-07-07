
rule Trojan_BAT_AgentTesla_EFV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 00 c5 03 bb 03 bf 03 b3 03 72 00 bc 03 ad 03 bd 03 bf 03 c2 03 20 00 bf 03 20 00 9a 03 cd 03 c1 03 b9 03 65 00 c2 03 2c 00 20 00 bf 03 20 00 b2 03 c1 03 ac 03 c7 03 61 00 c2 03 } //1
		$a_01_1 = {4b 00 bd 03 b1 03 b8 03 65 00 c3 03 c4 03 b5 03 20 00 c4 03 b9 03 79 00 } //1
		$a_01_2 = {74 00 72 00 75 00 6d 00 70 00 } //1 trump
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {54 6f 55 49 6e 74 33 32 } //1 ToUInt32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}