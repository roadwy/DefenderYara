
rule Trojan_Win32_Fragtor_ND_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4d d8 81 e1 01 00 00 80 79 05 49 83 c9 fe 41 85 c9 74 0b 8b 55 d8 83 c2 01 89 55 d8 eb e1 } //05 00 
		$a_81_1 = {67 63 72 79 } //00 00  gcry
	condition:
		any of ($a_*)
 
}