
rule Backdoor_Linux_Gafgyt_AH_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.AH!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 6e 64 48 54 54 50 48 65 78 } //01 00  SendHTTPHex
		$a_00_1 = {53 65 6e 64 53 54 44 48 45 58 } //01 00  SendSTDHEX
		$a_00_2 = {54 53 6f 75 72 63 65 20 45 6e 67 69 6e 65 20 51 75 65 72 79 20 2b 20 2f 78 35 34 2f 78 35 33 2f 78 36 66 2f 78 37 35 2f 78 37 32 2f 78 36 33 2f 78 36 35 2f 78 32 30 2f 78 34 35 2f 78 36 65 2f 78 36 37 2f 78 36 39 2f 78 36 65 2f 78 36 35 2f 78 32 30 2f 78 35 31 2f 78 37 35 2f 78 36 35 2f 78 37 32 2f 78 37 39 } //02 00  TSource Engine Query + /x54/x53/x6f/x75/x72/x63/x65/x20/x45/x6e/x67/x69/x6e/x65/x20/x51/x75/x65/x72/x79
		$a_00_3 = {76 73 65 61 74 74 61 63 6b } //00 00  vseattack
	condition:
		any of ($a_*)
 
}