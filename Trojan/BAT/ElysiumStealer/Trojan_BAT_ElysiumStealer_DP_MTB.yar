
rule Trojan_BAT_ElysiumStealer_DP_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_81_0 = {73 64 67 73 64 66 65 33 31 77 } //20 sdgsdfe31w
		$a_81_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_2 = {49 73 4c 6f 67 67 69 6e 67 } //1 IsLogging
		$a_81_3 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_81_4 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_5 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //1 ReverseDecode
		$a_81_6 = {52 65 73 6f 6c 76 65 } //1 Resolve
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=26
 
}