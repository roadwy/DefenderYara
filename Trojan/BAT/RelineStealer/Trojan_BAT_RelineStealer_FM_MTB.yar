
rule Trojan_BAT_RelineStealer_FM_MTB{
	meta:
		description = "Trojan:BAT/RelineStealer.FM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2e 70 64 62 } //1 .pdb
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_4 = {47 65 6e 65 72 61 74 65 32 35 36 42 69 74 73 4f 66 52 61 6e 64 6f 6d 45 6e 74 72 6f 70 79 } //1 Generate256BitsOfRandomEntropy
		$a_01_5 = {53 6f 44 4f 56 50 4e 53 52 7a 62 65 63 72 42 } //1 SoDOVPNSRzbecrB
		$a_01_6 = {76 48 61 65 62 55 6d 61 53 46 42 62 7a 6b 66 } //1 vHaebUmaSFBbzkf
		$a_01_7 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_8 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_9 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}