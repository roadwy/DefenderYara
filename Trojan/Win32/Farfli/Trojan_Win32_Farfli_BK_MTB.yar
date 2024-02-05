
rule Trojan_Win32_Farfli_BK_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 25 73 2e 65 78 65 } //01 00 
		$a_01_1 = {65 6b 69 6d 68 75 71 63 72 6f 61 6e 66 6c 76 7a 67 64 6a 74 78 79 70 73 77 62 } //01 00 
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 } //01 00 
		$a_01_3 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //01 00 
		$a_01_4 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}