
rule Trojan_Win32_Tromp_A{
	meta:
		description = "Trojan:Win32/Tromp.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 64 6c 6c 2e 64 6c 6c 00 4e 74 51 75 65 72 79 } //02 00 
		$a_01_1 = {89 45 fc 03 40 3c 8b 80 80 00 00 00 03 45 fc 89 45 f8 89 c6 8b 50 0c 89 d0 03 55 fc 85 c0 74 } //01 00 
		$a_03_2 = {40 00 8d 55 fc 52 6a 04 6a 20 50 ff 15 90 01 04 8b 35 90 01 04 bf 90 01 04 b9 20 00 00 00 f3 a4 8b 3d 90 00 } //01 00 
		$a_01_3 = {74 00 61 00 73 00 6b 00 64 00 69 00 72 00 00 00 74 00 61 00 73 00 6b 00 64 00 69 00 72 00 00 00 61 64 76 } //00 00 
	condition:
		any of ($a_*)
 
}