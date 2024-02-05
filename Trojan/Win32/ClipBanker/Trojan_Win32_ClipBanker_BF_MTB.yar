
rule Trojan_Win32_ClipBanker_BF_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {70 79 69 2d 77 69 6e 64 6f 77 73 2d 6d 61 6e 69 66 65 73 74 2d 66 69 6c 65 6e 61 6d 65 20 63 72 79 70 74 6f 2d 79 61 6e 6b 2e 65 78 65 2e 6d 61 6e 69 66 65 73 74 } //01 00 
		$a_81_1 = {65 6d 61 69 6c 2e 5f 65 6e 63 6f 64 65 64 5f 77 6f 72 64 73 } //01 00 
		$a_81_2 = {68 74 74 70 2e 63 6f 6f 6b 69 65 6a 61 72 } //01 00 
		$a_81_3 = {65 6d 61 69 6c 2e 62 61 73 65 36 34 6d 69 6d 65 } //01 00 
		$a_81_4 = {6d 75 6c 74 69 70 72 6f 63 65 73 73 69 6e 67 2e 72 65 73 6f 75 72 63 65 5f 74 72 61 63 6b 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}