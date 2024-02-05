
rule Trojan_Win32_Kryptik_P_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.P!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 00 75 00 74 00 56 00 61 00 62 00 42 00 69 00 6e 00 } //01 00 
		$a_01_1 = {74 37 4b 74 27 4b 74 } //01 00 
		$a_01_2 = {54 6f 74 6f 74 61 } //01 00 
		$a_01_3 = {44 6f 63 68 6c 61 6e 64 20 50 6f 63 68 6c 61 6e 64 } //01 00 
		$a_01_4 = {73 75 74 6f 72 69 20 77 61 75 75 } //00 00 
	condition:
		any of ($a_*)
 
}