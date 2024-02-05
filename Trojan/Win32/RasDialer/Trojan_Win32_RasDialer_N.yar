
rule Trojan_Win32_RasDialer_N{
	meta:
		description = "Trojan:Win32/RasDialer.N,SIGNATURE_TYPE_PEHSTR,2e 01 2e 01 06 00 00 64 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 57 61 72 65 5c 56 69 73 69 6f 20 52 41 53 20 53 63 72 69 70 74 } //64 00 
		$a_01_1 = {25 73 5c 25 73 2e 6c 6e 6b } //64 00 
		$a_01_2 = {52 61 73 44 69 61 6c 41 } //01 00 
		$a_01_3 = {2f 6d 69 6e } //01 00 
		$a_01_4 = {61 64 75 6c 74 } //01 00 
		$a_01_5 = {70 6f 72 6e } //00 00 
	condition:
		any of ($a_*)
 
}