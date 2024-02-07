
rule Trojan_Win32_Redline_PZE_MTB{
	meta:
		description = "Trojan:Win32/Redline.PZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 2f b4 47 e2 } //01 00 
		$a_01_1 = {e2 d8 2b db d9 dc e4 d9 ea de 2b e8 ea dd dd dc d7 2b e9 e6 2b d9 d6 dd 2b e2 dd 2b 07 fc f8 2b de dc e7 e6 1d } //01 00 
		$a_01_2 = {c2 b2 4e 58 4b 55 70 e2 9e 12 57 0e 0a a5 55 eb fd 71 51 b7 a0 a1 b1 aa fe fe a2 58 97 4c 15 bc 51 87 84 63 66 79 d1 55 44 d1 d7 9b ec 35 04 7d b7 e6 17 ab } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}