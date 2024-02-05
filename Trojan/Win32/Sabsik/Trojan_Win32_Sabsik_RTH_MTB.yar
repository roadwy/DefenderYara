
rule Trojan_Win32_Sabsik_RTH_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 0a 00 "
		
	strings :
		$a_81_0 = {69 33 38 36 5c 63 68 6b 65 73 70 2e 63 } //0a 00 
		$a_81_1 = {44 3a 5c 34 32 33 34 32 33 34 32 33 34 32 33 34 32 33 34 32 33 34 32 33 34 32 33 34 32 33 34 2e 70 64 62 } //01 00 
		$a_81_2 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //01 00 
		$a_81_3 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f 57 } //01 00 
		$a_81_4 = {47 65 74 53 79 73 74 65 6d 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}