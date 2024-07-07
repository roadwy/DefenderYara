
rule Trojan_BAT_AgentTesla_PSFV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {72 7f 00 00 70 0a 06 28 90 01 03 0a 25 26 0b 28 90 01 03 0a 25 26 07 16 07 8e 69 6f 90 01 03 0a 25 26 0a 28 90 01 03 0a 25 26 06 6f 90 01 03 0a 25 26 0c 90 00 } //5
		$a_01_1 = {49 50 54 56 20 54 6f 6f 6c 73 } //1 IPTV Tools
		$a_01_2 = {41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 4d 6f 64 65 } //1 AuthenticationMode
		$a_01_3 = {49 45 6e 75 6d 65 72 61 62 6c 65 } //1 IEnumerable
		$a_01_4 = {48 61 73 68 41 6c 67 6f 72 69 74 68 6d } //1 HashAlgorithm
		$a_01_5 = {53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d } //1 SymmetricAlgorithm
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}