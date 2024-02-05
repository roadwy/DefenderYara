
rule Trojan_Win32_Rifdoor_RA_MTB{
	meta:
		description = "Trojan:Win32/Rifdoor.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 72 6f 79 20 53 6f 75 72 63 65 20 43 6f 64 65 5c 74 63 70 31 73 74 5c 72 69 66 6c 65 5c 52 65 6c 65 61 73 65 5c 72 69 66 6c 65 2e 70 64 62 } //01 00 
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 55 70 64 61 74 65 5c 77 75 61 75 63 6c 74 2e 65 78 65 } //01 00 
		$a_01_2 = {4d 55 54 45 58 33 39 34 30 33 39 5f 34 39 33 30 30 32 33 } //00 00 
	condition:
		any of ($a_*)
 
}