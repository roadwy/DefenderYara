
rule Trojan_Win32_Small_DJ{
	meta:
		description = "Trojan:Win32/Small.DJ,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 73 61 73 73 2e 65 78 65 00 00 00 46 61 69 6c 20 54 6f 20 63 72 65 61 74 65 20 53 6e 61 70 20 53 68 6f 74 } //01 00 
		$a_01_1 = {49 73 20 47 6f 64 4d 6f 64 65 3a } //01 00 
		$a_01_2 = {46 61 69 6c 20 45 72 72 6f 72 21 } //01 00 
		$a_01_3 = {72 6f 6f 74 24 20 } //01 00 
		$a_01_4 = {8b ca c1 e2 07 c1 e9 19 0b ca 03 cf 8b ef 23 e9 8b d1 f7 d2 23 d3 0b d5 03 50 04 } //00 00 
	condition:
		any of ($a_*)
 
}