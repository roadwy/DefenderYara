
rule Trojan_Win32_ShipUp_GZN_MTB{
	meta:
		description = "Trojan:Win32/ShipUp.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {41 f7 de 55 44 31 34 24 5d 48 3b c5 44 84 ee 4d } //05 00 
		$a_03_1 = {26 32 19 54 94 56 b7 2c b3 11 81 b3 90 01 04 6c f3 48 84 31 9b 90 01 04 48 13 23 13 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}