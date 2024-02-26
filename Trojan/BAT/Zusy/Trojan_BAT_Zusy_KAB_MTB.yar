
rule Trojan_BAT_Zusy_KAB_MTB{
	meta:
		description = "Trojan:BAT/Zusy.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {a2 fd 16 f9 d4 15 f2 75 f4 2f 70 63 4f e9 b1 02 00 47 9f d1 ab 3e 73 a1 ba 5e 22 } //01 00 
		$a_01_1 = {9e fc 6b 19 f2 0a 6c f8 eb 33 23 71 c9 69 6b 90 91 63 c3 d5 d7 e7 63 f9 } //01 00 
		$a_01_2 = {61 65 64 72 66 62 69 78 } //00 00  aedrfbix
	condition:
		any of ($a_*)
 
}