
rule Trojan_Win32_Emotet_DV_bit{
	meta:
		description = "Trojan:Win32/Emotet.DV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0 } //01 00 
		$a_03_1 = {15 18 00 00 00 31 90 01 01 8b 90 01 01 30 8b 90 01 01 0c 90 00 } //01 00 
		$a_03_2 = {31 d2 f7 f1 8b 0d 90 01 04 8a 1c 11 8b 4d 90 01 01 8b 55 90 01 01 8a 3c 11 28 df 88 3c 11 81 c2 ff 00 00 00 8b 75 90 01 01 39 f2 89 55 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}