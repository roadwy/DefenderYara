
rule Trojan_WinNT_Whycan_A{
	meta:
		description = "Trojan:WinNT/Whycan.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 e9 00 20 22 00 0f 90 01 05 83 e9 05 74 90 01 01 83 e9 06 74 90 01 01 c7 45 d4 32 02 00 c0 90 00 } //01 00 
		$a_02_1 = {8b 7b 0c 85 ff 0f 84 90 01 04 80 bf 8a 63 00 00 01 0f 85 90 01 04 c7 45 90 01 05 8d b7 a8 2a 00 00 90 00 } //01 00 
		$a_02_2 = {8d 86 50 14 00 00 8b 4d 90 01 01 8d 1c 31 8b d3 2b d0 0f b7 08 66 89 0c 02 90 00 } //01 00 
		$a_02_3 = {8b f3 a5 66 a5 50 a4 e8 90 01 04 33 c0 8b fb ab 66 ab 5e aa 5b 90 00 } //01 00 
		$a_00_4 = {0f b7 07 b9 6e 6b 00 00 66 3b c1 75 } //00 00 
		$a_00_5 = {5d 04 00 00 } //68 1a 
	condition:
		any of ($a_*)
 
}