
rule Trojan_Win32_Emotet_V_bit{
	meta:
		description = "Trojan:Win32/Emotet.V!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6f 6f 6b 00 66 61 63 65 00 6c 75 63 6b 00 25 58 25 50 } //01 00 
		$a_03_1 = {89 c1 83 e1 1f 8b 15 90 01 04 8a 1c 0a 8b 4d 90 01 01 8a 3c 01 28 df 88 3c 01 05 ff 00 00 00 8b 55 90 01 01 39 d0 89 45 90 01 01 72 90 00 } //01 00 
		$a_03_2 = {eb 23 8b 45 90 01 01 8b 4d 90 01 01 01 c8 8b 55 90 01 01 8b 34 90 01 01 8b 7c 02 04 8b 5d 90 01 01 01 de 8b 4d 90 01 01 11 cf 89 34 02 89 7c 02 04 90 00 } //01 00 
		$a_01_3 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}