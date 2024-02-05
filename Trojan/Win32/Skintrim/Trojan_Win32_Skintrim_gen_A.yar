
rule Trojan_Win32_Skintrim_gen_A{
	meta:
		description = "Trojan:Win32/Skintrim.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {eb 5c 8d 8c 24 28 01 00 00 68 90 01 04 51 ff d7 8b f0 83 c4 08 85 f6 0f 84 ee 00 00 00 b9 41 00 00 00 33 c0 8d 7c 24 20 8d 54 24 20 f3 ab 68 04 01 00 00 52 aa ff 15 90 01 04 68 90 01 04 ff 15 90 00 } //01 00 
		$a_02_1 = {e9 cc 01 00 00 8d 8c 24 2c 01 00 00 68 90 01 04 51 ff d6 83 c4 08 89 44 24 10 85 c0 74 3e b9 41 00 00 00 33 c0 8d 7c 24 24 8d 54 24 24 f3 ab 68 04 01 00 00 52 aa ff 15 90 01 04 68 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}