
rule Trojan_Win32_ShipUp_GZY_MTB{
	meta:
		description = "Trojan:Win32/ShipUp.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {30 00 00 68 ae 0c 02 00 6a 00 } //05 00 
		$a_03_1 = {1e 32 00 40 c6 05 90 01 05 0b dd f3 7e 90 00 } //01 00 
		$a_80_2 = {62 66 70 65 6d 76 68 75 2e 76 63 64 } //bfpemvhu.vcd  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_ShipUp_GZY_MTB_2{
	meta:
		description = "Trojan:Win32/ShipUp.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 55 c4 89 55 cc 8b 45 dc 89 45 fc 8b 4d c8 89 4d ec 8b 55 c4 89 55 f4 8b 45 c4 89 45 d8 8b 4d ec 89 4d e0 8b 55 d8 89 55 f8 8b 45 f8 8b 08 33 4d e0 8b 55 f8 89 0a c7 45 c0 41 3c 00 00 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}