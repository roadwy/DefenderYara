
rule Trojan_WinNT_Duqu_D{
	meta:
		description = "Trojan:WinNT/Duqu.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 66 3b c1 73 90 01 01 0f b7 c7 6b c0 28 03 c6 8b 48 08 8b 50 10 3b ca 72 02 8b ca 8b 40 0c 3b d8 72 90 00 } //01 00 
		$a_03_1 = {66 c7 03 4d 5a 8b 0d 90 01 04 c7 04 19 50 45 00 00 8b 15 90 01 04 83 c4 0c 66 c7 04 1a 0b 01 a1 90 01 04 68 98 00 00 00 03 c3 6a 00 50 89 45 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}