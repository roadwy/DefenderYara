
rule Trojan_Win32_ShipUp_GMX_MTB{
	meta:
		description = "Trojan:Win32/ShipUp.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c4 fe c2 32 da 66 1b c5 80 ec c8 66 2b c6 88 0c 14 66 0f ba f8 90 01 01 fe c8 8b 06 90 00 } //01 00 
		$a_01_1 = {75 5a 54 32 67 77 41 52 72 44 } //01 00  uZT2gwARrD
		$a_01_2 = {2e 76 6d 70 30 } //00 00  .vmp0
	condition:
		any of ($a_*)
 
}