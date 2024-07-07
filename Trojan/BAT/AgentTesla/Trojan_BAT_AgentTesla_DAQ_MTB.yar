
rule Trojan_BAT_AgentTesla_DAQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {18 5b 0b 07 8d 90 01 01 00 00 01 0c 16 0d 38 90 01 01 00 00 00 02 09 18 5a 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 13 04 08 09 11 04 d2 9c 09 17 58 0d 09 07 32 df 90 00 } //2
		$a_01_1 = {49 00 20 00 73 00 65 00 65 00 20 00 69 00 74 00 } //1 I see it
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_4 = {74 00 75 00 74 00 6f 00 72 00 69 00 61 00 6c 00 2e 00 67 00 79 00 61 00 } //1 tutorial.gya
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}