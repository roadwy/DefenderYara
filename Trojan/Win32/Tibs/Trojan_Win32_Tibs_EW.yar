
rule Trojan_Win32_Tibs_EW{
	meta:
		description = "Trojan:Win32/Tibs.EW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {01 d0 89 c1 c3 89 eb 81 c3 10 19 00 00 89 e8 c3 83 c4 04 89 e1 89 fc 50 89 cc 39 dd 7e af c3 56 89 ee ad } //01 00 
		$a_01_1 = {83 c5 02 89 ef 83 c5 02 83 c7 02 89 f9 29 e9 89 ca 81 c2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Tibs_EW_2{
	meta:
		description = "Trojan:Win32/Tibs.EW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 41 6c 74 65 72 42 69 74 6d 61 70 00 00 00 50 61 67 65 53 65 74 75 70 44 6c 67 57 00 00 00 64 77 4f 4b 53 75 62 63 6c 61 73 73 00 00 } //01 00 
		$a_01_1 = {43 6f 6e 76 65 72 74 44 65 66 61 75 6c 74 4c 6f 63 61 6c 65 00 00 00 45 78 69 74 50 72 6f 63 65 73 73 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 47 65 74 43 50 49 6e 66 6f 45 78 57 } //00 00 
	condition:
		any of ($a_*)
 
}