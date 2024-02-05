
rule Trojan_Win32_Nadostarch_A{
	meta:
		description = "Trojan:Win32/Nadostarch.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6f 72 72 6e 61 64 6f 73 2e 72 75 } //01 00 
		$a_01_1 = {2f 73 65 6e 64 5f 73 6d 73 5f 32 34 2e 70 68 70 3f 74 65 6c 3d } //01 00 
		$a_01_2 = {2f 67 65 74 6f 70 2e 70 68 70 3f 74 65 6c 3d } //01 00 
		$a_01_3 = {26 61 72 68 69 64 3d } //01 00 
		$a_01_4 = {4b 45 59 20 52 52 52 } //01 00 
		$a_01_5 = {47 4f 20 52 52 52 } //03 00 
		$a_01_6 = {a5 a4 c7 85 f8 de ff ff 03 35 46 46 c7 85 f8 df ff ff 03 35 46 46 } //00 00 
		$a_01_7 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}