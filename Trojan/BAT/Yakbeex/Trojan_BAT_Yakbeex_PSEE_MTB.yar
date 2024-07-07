
rule Trojan_BAT_Yakbeex_PSEE_MTB{
	meta:
		description = "Trojan:BAT/Yakbeex.PSEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {06 17 64 0a 07 06 59 1f 1f 64 13 04 07 06 11 04 17 59 5f 59 0b 08 17 62 17 11 04 59 60 0c 06 20 00 00 00 01 41 15 00 00 00 07 1e 62 02 7b 3e 00 00 04 6f 9c 00 00 0a d2 60 0b 06 1e 62 0a 09 17 59 0d 09 16 } //5
		$a_01_1 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_01_2 = {47 65 74 48 61 73 68 43 6f 64 65 } //1 GetHashCode
		$a_01_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}