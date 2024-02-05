
rule Trojan_Win32_Hawkeye_PA_MTB{
	meta:
		description = "Trojan:Win32/Hawkeye.PA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 61 73 73 77 6f 72 64 53 74 65 61 6c 65 72 } //01 00 
		$a_01_1 = {4b 65 79 53 74 72 6f 6b 65 4c 6f 67 67 65 72 } //01 00 
		$a_01_2 = {41 6e 74 69 56 69 72 75 73 4b 69 6c 6c 65 72 } //01 00 
		$a_01_3 = {48 00 61 00 77 00 6b 00 45 00 79 00 65 00 20 00 52 00 65 00 62 00 6f 00 72 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}