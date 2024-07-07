
rule Trojan_BAT_AgentTesla_MBCB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 9a 1f 10 28 90 02 06 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 90 00 } //10
		$a_01_1 = {4d 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 2e 00 50 00 61 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 } //10 Manning.Passenger
		$a_01_2 = {47 65 74 4f 62 6a 65 63 74 } //1 GetObject
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {53 70 6c 69 74 } //1 Split
		$a_01_5 = {54 6f 42 79 74 65 } //1 ToByte
		$a_01_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=23
 
}