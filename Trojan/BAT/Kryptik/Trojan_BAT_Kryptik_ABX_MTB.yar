
rule Trojan_BAT_Kryptik_ABX_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ABX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {25 16 03 a2 6f 90 02 09 0b 07 6f 90 02 04 1f 09 9a 0c 14 d0 90 02 0f 18 8d 90 02 04 25 16 08 a2 25 17 19 8d 90 02 04 25 16 7e 90 02 04 a2 25 17 90 00 } //0a 00 
		$a_03_1 = {a2 25 18 72 90 02 04 a2 a2 25 0d 14 14 18 8d 90 02 04 25 16 17 9c 25 13 04 17 28 90 02 04 26 11 04 16 91 2d 02 2b 09 09 16 9a 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}