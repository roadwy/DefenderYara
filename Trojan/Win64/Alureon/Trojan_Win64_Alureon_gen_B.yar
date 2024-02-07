
rule Trojan_Win64_Alureon_gen_B{
	meta:
		description = "Trojan:Win64/Alureon.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 43 46 00 00 66 39 03 74 90 01 01 b8 43 44 00 00 66 39 03 75 90 00 } //01 00 
		$a_03_1 = {48 b8 14 00 00 00 80 f7 ff ff 8b 00 48 89 0d 90 01 04 48 8d 0d 90 01 04 89 05 90 01 04 ff 15 90 00 } //01 00 
		$a_03_2 = {49 8b 40 18 48 8d 35 90 01 04 48 8b f8 b9 00 02 00 00 f3 a4 48 8b 03 48 85 c0 74 90 01 01 4c 8b 43 08 90 00 } //01 00 
		$a_01_3 = {49 00 4e 00 20 00 4d 00 49 00 4e 00 54 00 } //00 00  IN MINT
	condition:
		any of ($a_*)
 
}