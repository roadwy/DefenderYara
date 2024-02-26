
rule Trojan_BAT_Heracles_KAF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {5f 2b 1d 03 6f 90 01 01 00 00 0a 0c 2b 17 08 06 08 06 93 02 7b 90 01 01 00 00 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a 16 2f 02 2b 05 2b dd 0a 2b c8 90 00 } //05 00 
		$a_01_1 = {e8 53 e8 41 e8 04 e8 00 e8 01 1d 83 f8 a6 f8 b3 } //00 00 
	condition:
		any of ($a_*)
 
}