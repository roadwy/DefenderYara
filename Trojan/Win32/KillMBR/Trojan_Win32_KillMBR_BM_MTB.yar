
rule Trojan_Win32_KillMBR_BM_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 6c 69 67 68 74 47 6c 69 6d 6d 65 72 5f 56 69 72 75 73 } //01 00 
		$a_01_1 = {76 31 2e 30 20 4d 42 52 4b 69 6c 6c 65 72 20 6e 65 77 } //01 00 
		$a_01_2 = {42 61 62 75 6b 52 61 6e 73 6f 6d 77 61 72 65 53 6f 75 72 63 65 43 6f 64 65 } //01 00 
		$a_01_3 = {4d 42 52 4c 6f 63 6b 2d 6d 61 73 74 65 72 } //01 00 
		$a_01_4 = {4b 69 6c 6c 4d 62 72 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}