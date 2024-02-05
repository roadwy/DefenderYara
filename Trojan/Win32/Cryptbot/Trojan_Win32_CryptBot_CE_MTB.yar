
rule Trojan_Win32_CryptBot_CE_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 8a 44 05 10 88 04 0a b9 90 01 04 6b d1 90 01 01 b8 90 01 04 6b c8 90 01 01 8b 45 fc 8a 54 15 10 88 14 08 b8 90 01 04 d1 90 01 01 b9 90 01 04 d1 90 01 01 8b 55 fc 8a 44 05 10 88 04 0a b9 90 01 04 6b d1 03 b8 90 01 04 6b c8 03 8b 45 fc 8a 54 15 10 88 14 08 90 00 } //03 00 
		$a_81_1 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //02 00 
		$a_81_2 = {47 65 74 54 68 72 65 61 64 54 69 6d 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}