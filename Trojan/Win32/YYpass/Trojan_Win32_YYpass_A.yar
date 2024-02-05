
rule Trojan_Win32_YYpass_A{
	meta:
		description = "Trojan:Win32/YYpass.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 0b 83 c3 04 8b 32 83 c2 04 f3 a4 48 75 f1 } //01 00 
		$a_00_1 = {6c 69 62 65 69 74 61 38 37 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00 
		$a_01_2 = {b1 bb b5 c1 59 59 c3 dc c2 eb a3 ba 00 } //01 00 
		$a_00_3 = {64 75 6f 73 70 65 61 6b 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}