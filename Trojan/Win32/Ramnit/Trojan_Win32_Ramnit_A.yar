
rule Trojan_Win32_Ramnit_A{
	meta:
		description = "Trojan:Win32/Ramnit.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 8a 1c 32 32 1f 88 1f 47 4a e2 ed } //01 00 
		$a_01_1 = {6a 05 8f 45 f0 6a 04 8d 85 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ramnit_A_2{
	meta:
		description = "Trojan:Win32/Ramnit.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {51 52 56 57 6a 0c ff 75 08 e8 90 01 02 ff ff 89 90 01 02 83 c0 08 8b c8 8b 75 0c 6a 19 52 e8 90 01 02 ff ff 04 61 88 06 46 e2 f1 c6 06 00 68 90 00 } //01 00 
		$a_01_1 = {8b 4d 0c 8b 75 1c 8b 7d 08 8b 55 10 3b 55 10 75 04 03 55 14 4a 8a 1a 32 1f 83 7d 18 00 75 0f 88 1e 46 80 fb 00 74 1e 39 75 20 76 19 eb 07 0a db 75 03 ff 4d 18 47 4a e2 d3 ff 75 18 8f 45 fc 83 7d 18 00 75 bb } //00 00 
		$a_00_2 = {7e } //15 00 
	condition:
		any of ($a_*)
 
}