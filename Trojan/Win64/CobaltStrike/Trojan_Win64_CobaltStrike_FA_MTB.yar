
rule Trojan_Win64_CobaltStrike_FA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {54 68 65 20 72 65 73 6f 75 72 63 65 20 6f 77 6e 65 72 } //1 The resource owner
		$a_81_1 = {44 65 63 72 79 70 74 65 64 20 25 64 2e 2e 2e 20 28 25 64 20 25 25 29 20 69 20 3d 20 25 64 3b 20 66 75 6c 6c 5f 6c 65 6e 67 74 68 20 3d 20 25 64 } //1 Decrypted %d... (%d %%) i = %d; full_length = %d
		$a_81_2 = {44 65 63 72 79 70 74 65 64 20 25 64 2e 2e 2e 6f 6b 21 } //1 Decrypted %d...ok!
		$a_81_3 = {4f 6c 64 20 70 72 6f 74 65 63 74 25 64 20 } //1 Old protect%d 
		$a_81_4 = {5b 3d 5d 20 53 74 61 72 } //1 [=] Star
		$a_81_5 = {2a 2c 64 3a 2f 74 68 2f 64 73 2f 65 78 74 2f 61 61 64 } //1 *,d:/th/ds/ext/aad
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}