
rule Trojan_Win32_Ramnit_J_bit{
	meta:
		description = "Trojan:Win32/Ramnit.J!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 4d 5a 00 00 66 39 01 75 f3 8b 41 3c 03 c1 81 38 50 45 00 00 75 e6 b9 90 01 04 66 39 48 18 75 db 90 00 } //01 00 
		$a_03_1 = {8b 55 fc 83 c2 90 01 01 83 e2 90 01 01 8b 45 08 8b 4d fc 8b 75 08 8b 54 90 90 90 01 01 33 14 8e 8b 45 fc 83 c0 90 01 01 83 e0 90 01 01 8b 4d 08 89 54 81 90 01 01 eb 90 00 } //01 00 
		$a_03_2 = {ff 75 18 8b 35 90 01 04 8b ce ff 75 14 33 35 90 01 04 83 e1 1f ff 75 10 d3 ce ff 75 0c ff 75 08 85 f6 75 be 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}