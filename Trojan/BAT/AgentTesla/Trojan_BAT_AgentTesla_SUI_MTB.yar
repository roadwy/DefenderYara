
rule Trojan_BAT_AgentTesla_SUI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {3a 2f 2f 31 30 33 2e 37 34 2e 31 30 35 2e 37 38 2f 47 52 41 4e 41 44 41 2f 5a 6e 75 73 6c 2e 76 64 66 } //1 ://103.74.105.78/GRANADA/Znusl.vdf
		$a_81_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_2 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_SUI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {0b 16 0c 07 8e 69 0d 11 0a 1f 68 91 20 8e 00 00 00 59 13 09 38 9b fe ff ff 00 08 17 58 13 06 07 08 07 08 91 28 07 00 00 06 08 1f 16 5d 91 61 07 11 06 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 1e 13 09 } //1
		$a_81_1 = {46 44 45 46 43 54 4e 47 48 45 57 41 4f 52 52 38 43 5a 4a 46 } //1 FDEFCTNGHEWAORR8CZJF
		$a_81_2 = {54 65 68 63 69 7a 61 74 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Tehcizat.Properties
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}