
rule Trojan_BAT_AgentTesla_PSBO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {02 6f 1c 01 00 0a 13 09 38 05 01 00 00 12 09 28 1d 01 00 0a 13 05 11 04 2c 25 08 7e 43 00 00 04 28 bb 02 00 06 6f 77 00 00 0a 16 7e 43 00 00 04 28 bb 02 00 06 6f 1e 01 00 0a 6f 96 00 00 0a 17 13 04 12 05 28 1f 01 00 0a } //5
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //1 VirtualAllocExNuma
		$a_01_2 = {47 65 74 48 61 73 68 43 6f 64 65 } //1 GetHashCode
		$a_01_3 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //1 CryptoStreamMode
		$a_01_4 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}