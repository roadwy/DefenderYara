
rule Trojan_Win32_Fragtor_NE_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 55 f8 81 e2 01 00 00 80 79 05 4a 83 ca fe 42 85 d2 74 0b 8b 45 f8 83 c0 01 89 45 f8 eb e1 } //05 00 
		$a_81_1 = {67 63 72 79 } //00 00  gcry
	condition:
		any of ($a_*)
 
}