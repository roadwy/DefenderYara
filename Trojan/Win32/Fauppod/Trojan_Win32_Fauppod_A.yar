
rule Trojan_Win32_Fauppod_A{
	meta:
		description = "Trojan:Win32/Fauppod.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {78 50 2b 3d 5f 2e 70 64 62 00 } //01 00 
		$a_03_1 = {66 c7 00 4d 5a 90 02 03 c7 90 01 01 3c c0 00 00 00 c7 90 01 01 c0 00 00 00 50 45 90 00 } //01 00 
		$a_03_2 = {e8 de ff ff ff 40 90 0a 1a 00 89 18 89 f0 01 05 90 01 04 89 ea 01 15 90 00 } //01 00 
		$a_03_3 = {e8 df ff ff ff 40 90 0a 2a 00 e8 90 01 04 89 d8 a3 90 01 04 89 f0 31 05 90 01 04 89 ea 01 15 90 00 } //01 00 
		$a_01_4 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0 } //00 00 
		$a_00_5 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}