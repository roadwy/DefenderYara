
rule Trojan_Win32_Fragtor_KAE_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 0b 81 c0 90 01 04 29 d7 81 e1 90 01 04 81 ef 90 01 04 f7 d2 31 0e f7 d2 29 fa 46 47 4f 43 29 c2 89 c7 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}