
rule Trojan_BAT_Cobaltstrike_EH_MTB{
	meta:
		description = "Trojan:BAT/Cobaltstrike.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 00 2e 00 30 00 2e 00 38 00 34 00 36 00 39 00 2e 00 36 00 37 00 34 00 35 00 } //01 00  1.0.8469.6745
		$a_01_1 = {43 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  Chrome.exe
		$a_01_2 = {72 61 6e 67 65 44 65 63 6f 64 65 72 } //01 00  rangeDecoder
		$a_01_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}