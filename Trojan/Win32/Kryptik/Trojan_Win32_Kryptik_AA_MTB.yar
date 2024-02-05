
rule Trojan_Win32_Kryptik_AA_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 45 e4 33 45 f0 89 45 e4 8b 4d ec 33 4d e4 89 4d ec c7 05 c8 3a b9 02 00 00 00 00 8b 45 ec 01 05 c8 3a b9 02 8b 45 ec 29 45 f4 8b 55 f4 c1 e2 04 89 55 e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0 81 3d d4 3b b9 02 be 01 00 00 75 11 } //01 00 
		$a_03_1 = {c7 05 d0 3a b9 02 b4 02 d7 cb c7 05 d4 3a b9 02 ff ff ff ff 8b 55 f4 8b 4d cc d3 ea 89 55 ec 8b 45 ec 03 45 d4 89 45 ec 8b 4d e4 33 4d f0 89 4d e4 8b 45 ec 31 45 e4 8b 45 e4 29 45 d0 8b 55 d8 52 8d 45 e8 50 e8 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}