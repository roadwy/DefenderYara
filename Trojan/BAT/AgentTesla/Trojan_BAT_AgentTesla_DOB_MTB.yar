
rule Trojan_BAT_AgentTesla_DOB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 75 90 01 03 1b 09 91 61 90 00 } //1
		$a_01_1 = {02 02 8e 69 17 59 91 1f 70 61 0b } //1
		$a_01_2 = {00 53 65 6c 65 63 74 6f 72 58 00 } //1
		$a_01_3 = {00 54 6f 49 6e 74 33 32 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}