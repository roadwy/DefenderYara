
rule Trojan_Win32_Vodvit_B{
	meta:
		description = "Trojan:Win32/Vodvit.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {b2 6c b3 6f b9 34 00 00 00 33 c0 8d bc 24 90 01 04 88 94 24 90 01 04 88 94 24 90 01 04 c6 84 24 90 01 04 64 90 00 } //01 00 
		$a_01_1 = {61 75 5f 75 70 64 61 74 61 2e 65 78 65 } //01 00 
		$a_01_2 = {61 75 63 6f 64 65 5f 31 39 39 32 5f 30 39 31 35 } //01 00 
		$a_01_3 = {61 75 6c 69 73 74 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}