
rule Trojan_BAT_ElysiumStealer_DP_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 14 00 "
		
	strings :
		$a_81_0 = {73 64 67 73 64 66 65 33 31 77 } //01 00  sdgsdfe31w
		$a_81_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_2 = {49 73 4c 6f 67 67 69 6e 67 } //01 00  IsLogging
		$a_81_3 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00  Decompress
		$a_81_4 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_81_5 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //01 00  ReverseDecode
		$a_81_6 = {52 65 73 6f 6c 76 65 } //00 00  Resolve
	condition:
		any of ($a_*)
 
}