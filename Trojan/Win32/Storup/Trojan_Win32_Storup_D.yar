
rule Trojan_Win32_Storup_D{
	meta:
		description = "Trojan:Win32/Storup.D,SIGNATURE_TYPE_PEHSTR_EXT,ffffffca 00 ffffffca 00 0a 00 00 64 00 "
		
	strings :
		$a_01_0 = {00 25 2b 72 37 34 40 00 } //64 00  ─爫㐷@
		$a_01_1 = {00 62 2d 79 34 2d 3d 00 } //01 00  戀礭ⴴ=
		$a_01_2 = {2e 6a 70 67 00 } //01 00 
		$a_03_3 = {80 00 f5 ff 45 fc 39 4d fc 72 e3 90 01 1a 80 00 2e ff 45 fc 39 4d fc 72 e3 90 00 } //01 00 
		$a_03_4 = {74 04 80 04 90 01 01 f5 40 3b c1 72 e6 90 01 17 80 04 90 01 01 2e 40 3b c1 72 e6 90 00 } //01 00 
		$a_01_5 = {8b 4d 0c 8a 14 08 80 c2 f5 eb 09 8b 4d 0c 8a 14 08 80 c2 2e 88 14 08 40 3b } //01 00 
		$a_03_6 = {f5 eb 03 80 90 01 01 2e 88 90 01 02 40 3b 90 00 } //01 00 
		$a_03_7 = {74 06 80 04 90 01 01 f5 eb 04 80 04 90 01 01 2e 90 01 01 3b 90 01 01 7c 90 00 } //01 00 
		$a_01_8 = {2c 0b 8b 4d 0c 03 4d e4 88 01 eb 12 8b 55 0c 03 55 e4 8a 02 04 2e 8b 4d 0c 03 4d e4 88 01 } //01 00 
		$a_01_9 = {8a 08 80 c1 2e 8b 95 f4 fe ff ff 03 95 b4 f8 ff ff 88 0a eb a5 } //00 00 
	condition:
		any of ($a_*)
 
}