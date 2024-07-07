
rule Trojan_BAT_AgentTesla_AABC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AABC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 8e 69 08 16 08 8e 69 28 90 01 01 00 00 0a 03 07 28 90 01 01 00 00 06 0d 09 6f 90 01 01 00 00 0a 13 04 11 04 08 16 08 8e 69 6f 90 01 01 00 00 0a 13 05 28 90 01 01 00 00 0a 11 05 6f 90 01 01 00 00 0a 13 06 dd 90 01 01 00 00 00 11 04 39 90 01 01 00 00 00 11 04 6f 90 01 01 00 00 0a dc 90 00 } //4
		$a_01_1 = {54 00 68 00 69 00 73 00 49 00 73 00 41 00 53 00 65 00 63 00 72 00 65 00 74 00 4b 00 65 00 79 00 } //1 ThisIsASecretKey
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}