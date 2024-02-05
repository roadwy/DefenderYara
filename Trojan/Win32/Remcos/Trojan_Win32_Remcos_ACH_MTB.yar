
rule Trojan_Win32_Remcos_ACH_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {31 07 8b 07 31 05 90 01 04 a1 90 1b 00 31 07 6a 04 68 00 10 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Remcos_ACH_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.ACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {31 07 8b 07 31 05 90 01 04 a1 90 1b 00 31 07 6a 04 68 00 10 00 00 90 00 } //01 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 59 61 6b 5c 44 65 73 6b 74 6f 70 5c 41 6c 74 5f 52 36 36 44 72 61 77 5c 54 5f 5f 5f 69 6d 67 46 69 67 2e 70 61 73 } //01 00 
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 59 61 6b 5c 44 65 73 6b 74 6f 70 5c 41 6c 74 5f 52 36 36 44 72 61 77 5c 54 5f 5f 52 47 72 6f 75 70 2e 70 61 73 } //01 00 
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 59 61 6b 5c 44 65 73 6b 74 6f 70 5c 41 6c 74 5f 52 36 36 44 72 61 77 5c 54 5f 5f 52 55 6e 64 6f 2e 70 61 73 } //01 00 
		$a_01_4 = {43 3a 5c 55 73 65 72 73 5c 59 61 6b 5c 44 65 73 6b 74 6f 70 5c 41 6c 74 5f 52 36 36 44 72 61 77 5c 54 5f 5f 52 53 65 6c 46 72 6d 2e 70 61 73 } //01 00 
		$a_01_5 = {43 3a 5c 55 73 65 72 73 5c 59 61 6b 5c 44 65 73 6b 74 6f 70 5c 41 6c 74 5f 52 36 36 44 72 61 77 5c 54 5f 5f 52 43 6f 72 65 2e 70 61 73 } //00 00 
	condition:
		any of ($a_*)
 
}