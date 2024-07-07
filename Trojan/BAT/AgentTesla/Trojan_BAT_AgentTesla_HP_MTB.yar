
rule Trojan_BAT_AgentTesla_HP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {0a 02 72 75 00 00 70 6f 90 01 03 0a 2c 3e 06 02 6f 90 01 03 0a 0b 07 16 73 90 01 03 0a 0c 73 90 01 03 0a 0d 08 09 28 90 01 03 06 09 16 6a 6f 90 01 03 0a 09 13 04 de 1c 90 00 } //1
		$a_81_1 = {2e 63 6f 6d 70 72 65 73 73 65 64 } //1 .compressed
		$a_81_2 = {63 6c 69 65 6e 74 63 6f 72 65 } //1 clientcore
		$a_81_3 = {63 6f 73 74 75 72 61 } //1 costura
		$a_81_4 = {44 72 6f 70 62 6f 78 2e 41 70 69 } //1 Dropbox.Api
		$a_81_5 = {44 63 53 76 63 } //1 DcSvc
		$a_81_6 = {52 42 53 76 63 } //1 RBSvc
		$a_81_7 = {52 75 6e 74 69 6d 65 42 72 6f 6b 65 72 } //1 RuntimeBroker
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}