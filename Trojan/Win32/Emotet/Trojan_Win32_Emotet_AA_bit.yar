
rule Trojan_Win32_Emotet_AA_bit{
	meta:
		description = "Trojan:Win32/Emotet.AA!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 23 8b 45 90 01 01 8b 4d 90 01 01 01 c8 8b 55 90 01 01 8b 34 90 01 01 8b 7c 02 04 8b 5d 90 01 01 01 de 8b 4d 90 01 01 11 cf 89 34 02 89 7c 02 04 90 00 } //01 00 
		$a_03_1 = {89 c1 83 e1 1f 8b 15 90 01 04 8a 1c 0a 8b 4d 90 01 01 8a 3c 01 28 df 88 3c 01 05 ff 00 00 00 8b 55 90 01 01 39 d0 89 45 90 01 01 72 90 00 } //01 00 
		$a_03_2 = {89 f1 01 c1 83 c1 08 8b 01 8b 4d 90 01 01 c6 01 90 01 01 8b 4d 90 01 01 29 cf 8b 4d 90 01 01 01 f9 01 d9 8b 7d 90 01 01 89 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}