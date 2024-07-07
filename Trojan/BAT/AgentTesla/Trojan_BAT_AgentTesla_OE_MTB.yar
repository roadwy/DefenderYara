
rule Trojan_BAT_AgentTesla_OE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {4b 65 79 65 64 43 6f 6c 6c 65 63 74 69 6f 6e 2e 49 6e 6e 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 KeyedCollection.Inner.resources
		$a_81_1 = {24 37 66 36 33 35 31 35 39 2d 63 31 62 61 2d 34 61 63 37 2d 39 39 61 37 2d 64 36 38 33 66 64 36 30 62 31 36 38 } //1 $7f635159-c1ba-4ac7-99a7-d683fd60b168
		$a_81_2 = {43 79 63 4d 61 69 6c 4d 53 47 } //1 CycMailMSG
		$a_81_3 = {45 6e 76 4d 61 69 6c 4d 53 47 } //1 EnvMailMSG
		$a_81_4 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_6 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}