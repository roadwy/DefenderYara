
rule Trojan_Win32_GuLoader_RG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6c 76 62 72 79 6c 6c 75 70 70 65 74 73 } //01 00 
		$a_01_1 = {41 6e 74 69 6b 76 69 74 65 74 73 66 6f 72 72 65 74 6e 69 6e 67 65 72 32 } //01 00 
		$a_01_2 = {41 6d 66 69 62 69 65 74 61 6e 6b } //01 00 
		$a_00_3 = {46 00 4c 00 75 00 78 00 4f 00 69 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_GuLoader_RG_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 72 69 6e 76 65 6a 73 73 79 67 64 6f 6d 6d 65 6e 65 73 2e 53 69 67 } //01 00 
		$a_01_1 = {55 6e 69 6e 73 74 61 6c 6c 5c 45 6c 69 64 65 72 65 64 65 } //01 00 
		$a_01_2 = {41 62 6c 61 74 69 76 65 73 5c 45 79 65 73 69 67 68 74 2e 69 6e 69 } //01 00 
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 53 70 69 6f 6e 6b 61 6d 65 72 61 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}