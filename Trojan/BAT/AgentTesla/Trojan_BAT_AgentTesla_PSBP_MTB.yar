
rule Trojan_BAT_AgentTesla_PSBP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {00 73 5c 00 00 0a 0a 73 5d 90 01 03 0b 07 04 6f 5e 90 01 03 0c 06 08 6f 5f 90 01 03 0d 07 09 6f 60 90 01 03 10 02 72 54 a9 06 70 13 04 11 04 02 7b 18 00 00 04 73 4e 90 01 03 13 05 11 05 6f 4f 90 01 03 72 1b aa 06 70 90 00 } //01 00 
		$a_01_1 = {48 61 73 68 41 6c 67 6f 72 69 74 68 6d } //01 00  HashAlgorithm
		$a_01_2 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //01 00  ContainsKey
		$a_01_3 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_01_4 = {53 48 41 31 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00  SHA1CryptoServiceProvider
	condition:
		any of ($a_*)
 
}