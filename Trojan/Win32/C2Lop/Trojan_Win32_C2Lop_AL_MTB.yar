
rule Trojan_Win32_C2Lop_AL_MTB{
	meta:
		description = "Trojan:Win32/C2Lop.AL!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {81 00 47 86 c8 61 c3 c1 e0 04 89 01 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 29 08 c3 01 08 } //0a 00 
		$a_01_1 = {8b 45 e8 8b 4d f0 03 c3 d3 eb 89 45 cc } //00 00 
	condition:
		any of ($a_*)
 
}