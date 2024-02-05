
rule Trojan_WinNT_Hesock_A{
	meta:
		description = "Trojan:WinNT/Hesock.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 7b 10 01 74 90 01 01 83 7d 10 00 7c 90 01 01 8b 43 14 2d 05 01 01 00 74 90 01 01 83 e8 09 74 90 01 01 83 e8 06 74 90 01 01 2d ee ff ff 00 75 90 01 01 8b 4b 1c 56 8b 73 18 57 8b 7d 08 8b c1 83 c7 53 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 90 00 } //01 00 
		$a_01_1 = {8a 51 04 0f b7 c6 03 c7 30 10 8a 51 04 30 50 01 46 46 66 3b 71 10 72 } //00 00 
	condition:
		any of ($a_*)
 
}