
rule Trojan_Win64_Alureon_gen_J{
	meta:
		description = "Trojan:Win64/Alureon.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {5c 70 68 64 61 74 61 00 } //\phdata  01 00 
		$a_00_1 = {50 75 72 70 6c 65 48 61 7a 65 } //01 00 
		$a_01_2 = {b8 53 46 00 00 66 39 03 74 0a b8 53 44 00 00 66 39 03 75 } //01 00 
		$a_03_3 = {b9 10 27 00 00 ff 15 90 01 04 e9 90 16 48 8d 15 90 01 04 48 8d 0d 90 01 04 45 33 c0 ff 15 90 01 04 85 c0 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}