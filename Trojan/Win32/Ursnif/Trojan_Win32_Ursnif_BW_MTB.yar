
rule Trojan_Win32_Ursnif_BW_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 6c 6f 73 65 5c 45 69 67 68 74 5c 61 67 65 5c 6b 69 6e 67 5c 4f 72 67 61 6e 5c 73 65 61 5c 6d 75 73 69 63 5c 4b 69 6e 67 68 69 6c 6c 2e 70 64 62 } //01 00 
		$a_01_1 = {50 00 6c 00 61 00 6e 00 64 00 65 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_BW_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 72 65 61 64 20 6d 61 73 73 20 41 67 61 69 6e 62 61 74 20 68 75 6d 61 6e 20 63 61 75 73 65 } //01 00 
		$a_00_1 = {63 3a 5c 6c 69 66 65 5c 43 6f 70 79 5c 73 70 72 69 6e 67 5c 72 61 69 6e 5c 45 76 65 72 5c 6d 69 6e 64 5c 63 65 6e 74 5c 62 75 72 6e 43 6f 6c 64 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}