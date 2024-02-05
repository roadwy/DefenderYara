
rule Trojan_Win32_Redosdru_N{
	meta:
		description = "Trojan:Win32/Redosdru.N,SIGNATURE_TYPE_PEHSTR,20 00 20 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 6f 00 72 00 6c 00 61 00 6e 00 64 00 5c 00 44 00 65 00 6c 00 70 00 68 00 69 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 65 00 73 00 } //0a 00 
		$a_01_1 = {4f 00 6e 00 6c 00 69 00 6e 00 65 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //05 00 
		$a_01_2 = {2a 00 2e 00 74 00 6f 00 72 00 72 00 65 00 6e 00 74 00 } //05 00 
		$a_01_3 = {5b 00 43 00 4c 00 49 00 50 00 42 00 4f 00 41 00 52 00 44 00 20 00 45 00 4e 00 44 00 5d 00 } //02 00 
		$a_01_4 = {73 00 79 00 6e 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 6e 00 65 00 74 00 2f 00 73 00 63 00 72 00 69 00 70 00 74 00 73 00 } //01 00 
		$a_01_5 = {61 00 76 00 67 00 63 00 63 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_6 = {62 00 64 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_7 = {61 00 76 00 70 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_8 = {6e 00 6f 00 64 00 33 00 32 00 6b 00 72 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_9 = {62 00 64 00 61 00 67 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_10 = {6d 00 63 00 73 00 68 00 69 00 65 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_11 = {70 00 61 00 76 00 66 00 69 00 72 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}