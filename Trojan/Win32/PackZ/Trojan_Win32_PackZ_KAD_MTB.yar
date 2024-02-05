
rule Trojan_Win32_PackZ_KAD_MTB{
	meta:
		description = "Trojan:Win32/PackZ.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 1a 21 f9 f7 d7 81 e3 90 01 04 f7 d1 81 c6 90 01 04 31 18 81 c7 90 01 04 21 c9 21 fe 81 c0 90 01 04 29 f1 81 e9 90 01 04 21 f7 42 89 f1 81 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}