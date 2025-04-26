
rule Trojan_BAT_AgentTesla_NGI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {69 6e 74 65 67 72 61 6c 62 64 2e 63 6f 6d 2f 69 6e 71 75 69 72 79 2d 63 69 6d 2e 6a 70 67 } //1 integralbd.com/inquiry-cim.jpg
		$a_81_1 = {5a 74 6d 62 44 6f 77 5a 74 6d 62 6e 6c 5a 74 6d 62 6f 61 64 44 5a 74 6d 62 61 74 61 5a 74 6d 62 } //1 ZtmbDowZtmbnlZtmboadDZtmbataZtmb
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_5 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}