
rule Trojan_Win32_Redline_NEAF_MTB{
	meta:
		description = "Trojan:Win32/Redline.NEAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c1 c6 02 23 f8 4a f7 d6 81 f3 b2 c6 38 dc 81 ea 8f 8b da 56 23 1d 68 e4 4e 00 31 3d 78 e0 4e 00 81 eb b5 e8 ab 0e 89 1d c2 e4 4e 00 c1 e0 0b 8b 35 75 e3 4e 00 e2 c9 } //00 00 
	condition:
		any of ($a_*)
 
}