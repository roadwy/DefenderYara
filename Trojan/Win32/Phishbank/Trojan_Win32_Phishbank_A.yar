
rule Trojan_Win32_Phishbank_A{
	meta:
		description = "Trojan:Win32/Phishbank.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 2d 65 2d 6c 2d 6c 2d 42 2d 6f 2d 74 } //01 00 
		$a_01_1 = {73 74 61 72 74 5f 64 64 6f 73 } //01 00 
		$a_01_2 = {49 5f 46 55 43 4b 5f 44 45 41 44 5f 50 50 4c } //01 00 
		$a_01_3 = {2f 70 68 69 73 68 00 00 78 6d 61 79 61 62 61 6e 6b 2e 68 74 6d 6c } //01 00 
		$a_01_4 = {25 73 5c 25 73 5c 73 65 72 76 69 63 65 73 73 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}