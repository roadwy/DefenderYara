
rule Trojan_Win32_VBKrypt_BP_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {4e 6f 76 6f 5f 43 6f 6d 43 72 79 70 74 } //01 00 
		$a_81_1 = {47 65 6e 6f 6d 61 2e 76 62 70 } //01 00 
		$a_81_2 = {40 72 5f 44 65 63 6f 64 65 } //01 00 
		$a_81_3 = {4a 53 63 72 69 70 74 } //01 00 
		$a_81_4 = {68 72 65 66 } //00 00 
	condition:
		any of ($a_*)
 
}