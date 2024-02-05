
rule Trojan_Win32_Copak_RDA_MTB{
	meta:
		description = "Trojan:Win32/Copak.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {56 4a 8b 3c 24 83 c4 04 81 eb 01 00 00 00 57 21 da 21 d3 81 c2 45 c3 af b0 8b 0c 24 83 c4 04 01 da 81 c2 9f ea 88 a8 51 29 d2 43 8b 34 24 83 c4 04 81 ea 01 00 00 00 81 c2 21 57 ea 16 ba 8d 69 56 7f 40 09 db 81 f8 09 40 00 01 } //02 00 
		$a_01_1 = {93 b6 81 c1 04 00 00 00 39 d9 75 e9 89 f8 c3 } //00 00 
	condition:
		any of ($a_*)
 
}