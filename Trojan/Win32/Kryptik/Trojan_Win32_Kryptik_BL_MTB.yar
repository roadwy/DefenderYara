
rule Trojan_Win32_Kryptik_BL_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.BL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {bb 86 88 d6 00 09 c0 29 c1 40 e8 28 00 00 00 41 81 e8 d1 85 b2 6b 31 1e 89 c9 81 c6 02 00 00 00 21 c0 89 c8 39 d6 7c d8 81 c1 01 00 00 00 89 c9 } //01 00 
		$a_01_1 = {8d 1c 1f 81 c1 57 ce e8 e8 89 c1 09 c0 8b 1b 89 c0 81 e3 ff 00 00 00 81 e9 01 00 00 00 21 c0 47 40 68 f2 81 82 05 58 48 81 ff f4 01 00 00 75 05 bf 00 00 00 00 89 c8 01 c0 81 e9 ec d2 0f e9 } //00 00 
	condition:
		any of ($a_*)
 
}