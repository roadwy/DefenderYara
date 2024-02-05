
rule Trojan_Win32_Zusy_CF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 1c 31 8b 44 24 10 8a 54 3a 04 32 da 88 1c 31 41 3b c8 72 e0 } //02 00 
		$a_03_1 = {33 d3 c1 e8 08 8b 14 95 90 02 04 33 c2 41 3b ce 75 e0 90 00 } //01 00 
		$a_01_2 = {25 73 5c 25 73 2e 65 78 65 20 72 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}