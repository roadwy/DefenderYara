
rule Trojan_Win32_Pony_AS_MTB{
	meta:
		description = "Trojan:Win32/Pony.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {34 2d fd 1f 49 00 5f 7d 01 59 a3 94 94 33 e8 ce f3 b2 d1 5b 33 56 4b 3a 16 70 } //02 00 
		$a_01_1 = {3d d3 d7 4f 99 bf bc 04 70 54 56 b9 79 0d ac 53 f1 54 1d 58 0b 9e cb 5e 98 24 85 04 70 2a 6b f3 b3 e3 0b 84 7f 5c e3 14 26 4b b6 04 70 } //00 00 
	condition:
		any of ($a_*)
 
}