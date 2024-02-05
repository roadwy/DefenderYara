
rule Trojan_Win32_Vundo_gen_AM{
	meta:
		description = "Trojan:Win32/Vundo.gen!AM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_13_0 = {03 00 00 00 90 01 03 58 eb 90 14 83 c0 90 01 01 eb 90 14 ff e0 90 00 02 } //00 0f 
		$a_61_1 = {66 } //52 65 
		$a_2e_2 = {6c 6c 00 61 00 62 00 01 00 1f 03 03 c1 30 10 0f b6 85 90 01 02 ff ff 41 3b c8 7c df 39 75 90 01 01 8b 45 90 01 01 73 03 90 00 01 00 12 01 3b c6 74 0e 6a 04 ff 75 0c 53 ff d0 85 c0 0f 95 45 0b 00 00 5d 04 00 00 f4 0a 02 00 5c 20 00 00 09 0b 02 00 00 00 01 00 08 00 0a 00 ac 21 47 6f 6c 64 75 6e 2e 43 00 00 } //01 40 
	condition:
		any of ($a_*)
 
}