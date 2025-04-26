
rule Trojan_Win64_Lazy_WCD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.WCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 61 32 58 45 32 4d 64 4f 67 32 62 46 7a 6b 41 70 7a 6b 6c 39 2f } //5 Go build ID: "a2XE2MdOg2bFzkApzkl9/
		$a_81_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 34 42 38 2d 69 79 4e 6d 61 33 34 61 4b 79 79 50 72 69 45 70 2f } //5 Go build ID: "4B8-iyNma34aKyyPriEp/
		$a_81_2 = {44 65 6c 65 74 65 53 65 6c 66 } //1 DeleteSelf
		$a_81_3 = {49 6e 6a 65 63 74 50 72 6f 63 65 73 73 52 65 6d 6f 74 65 } //1 InjectProcessRemote
		$a_81_4 = {44 6c 6c 49 6e 6a 65 63 74 53 65 6c 66 } //1 DllInjectSelf
		$a_81_5 = {53 74 65 61 6c 5f 74 6f 6b 65 6e } //1 Steal_token
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=9
 
}