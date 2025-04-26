
rule Trojan_BAT_ElysiumStealer_EI_MTB{
	meta:
		description = "Trojan:BAT/ElysiumStealer.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 0d 00 00 "
		
	strings :
		$a_81_0 = {66 64 73 66 73 66 64 66 73 64 } //20 fdsfsfdfsd
		$a_81_1 = {66 61 66 61 73 64 73 61 64 } //20 fafasdsad
		$a_81_2 = {63 73 64 63 73 64 64 73 73 64 } //20 csdcsddssd
		$a_81_3 = {66 73 66 64 66 64 73 66 73 } //20 fsfdfdsfs
		$a_81_4 = {62 76 73 64 76 64 73 73 64 } //20 bvsdvdssd
		$a_81_5 = {67 64 66 67 64 66 67 64 66 67 } //20 gdfgdfgdfg
		$a_81_6 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_81_7 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_81_8 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_81_9 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_10 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //1 ReverseDecode
		$a_81_11 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //1 LzmaDecoder
		$a_81_12 = {52 65 73 6f 6c 76 65 } //1 Resolve
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=27
 
}