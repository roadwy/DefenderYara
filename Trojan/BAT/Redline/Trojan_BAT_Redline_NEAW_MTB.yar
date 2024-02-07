
rule Trojan_BAT_Redline_NEAW_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 2d 02 07 6f 90 01 01 00 00 0a 03 07 03 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 0c 06 72 90 01 01 09 00 70 08 28 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 26 07 17 58 0b 07 02 90 00 } //02 00 
		$a_01_1 = {2a 00 77 00 61 00 6c 00 6c 00 65 00 74 00 2a 00 } //02 00  *wallet*
		$a_01_2 = {6d 00 6f 00 7a 00 5f 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //02 00  moz_cookies
		$a_01_3 = {56 00 61 00 6c 00 76 00 65 00 5c 00 53 00 74 00 65 00 61 00 6d 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 } //00 00  Valve\SteamLogin Data
	condition:
		any of ($a_*)
 
}