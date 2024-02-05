
rule Trojan_Win32_Ninunarch_K{
	meta:
		description = "Trojan:Win32/Ninunarch.K,SIGNATURE_TYPE_PEHSTR,6f 00 6f 00 04 00 00 64 00 "
		
	strings :
		$a_01_0 = {37 37 27 23 1d 13 24 39 6e 6f 70 71 72 72 72 72 72 72 73 74 5e 67 75 5e 24 75 68 65 74 72 72 72 72 72 } //0a 00 
		$a_01_1 = {64 31 6f 32 6f 33 68 34 6b 35 74 36 74 37 6d 38 63 39 75 30 70 31 6b 32 69 33 75 34 74 } //01 00 
		$a_01_2 = {6c 61 62 65 6c 52 65 74 72 79 53 65 6e 64 53 4d 53 } //01 00 
		$a_01_3 = {51 46 74 70 44 54 50 } //00 00 
	condition:
		any of ($a_*)
 
}