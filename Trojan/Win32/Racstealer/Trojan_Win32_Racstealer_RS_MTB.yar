
rule Trojan_Win32_Racstealer_RS_MTB{
	meta:
		description = "Trojan:Win32/Racstealer.RS!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 73 24 8b 45 fc 33 d2 f7 75 14 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f be 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb cb } //01 00 
		$a_01_1 = {61 73 70 72 5f 6b 65 79 73 2e 69 6e 69 } //01 00  aspr_keys.ini
		$a_01_2 = {57 6d 4d 32 4d 7a 45 33 4e 57 6f 7a 4d 44 49 77 4d 7a 4a 6c 50 7a 30 38 5a 7a 30 } //00 00  WmM2MzE3NWozMDIwMzJlPz08Zz0
	condition:
		any of ($a_*)
 
}