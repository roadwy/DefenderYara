
rule Trojan_Win32_Slenkill_gen_A{
	meta:
		description = "Trojan:Win32/Slenkill.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 7d f8 08 7d 39 8b 4d 08 03 4d f8 0f be 91 90 01 04 33 55 fc 8b 45 f4 03 45 f8 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 81 e2 ff 00 00 80 79 08 90 00 } //01 00 
		$a_03_1 = {6a 64 ff 15 90 01 04 6a 00 68 90 01 04 8d 4d 90 01 01 e8 90 01 04 50 ff 15 90 01 04 c7 45 90 01 01 00 00 00 00 eb 09 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 83 7d 90 01 01 18 7d 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}