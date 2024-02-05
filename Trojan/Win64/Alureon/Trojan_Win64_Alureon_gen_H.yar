
rule Trojan_Win64_Alureon_gen_H{
	meta:
		description = "Trojan:Win64/Alureon.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 69 6e 6a 65 63 74 73 5f 62 65 67 69 6e 5f 36 34 5d 00 } //01 00 
		$a_01_1 = {4d 41 52 4b 45 52 5f 41 46 46 49 44 00 00 00 00 4d 41 52 4b 45 52 5f 53 55 42 49 44 00 } //01 00 
		$a_00_2 = {41 bc 3f 00 00 c0 41 3b c4 75 63 48 8b 53 08 48 8b cf e8 } //01 00 
		$a_00_3 = {66 81 3a 4d 5a 75 0d 48 63 42 3c 81 3c 10 50 45 00 00 74 09 48 81 ea 00 10 00 00 75 e3 48 8d } //00 00 
	condition:
		any of ($a_*)
 
}