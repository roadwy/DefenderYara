
rule PUA_MacOS_Searchproxy_D_MTB{
	meta:
		description = "PUA:MacOS/Searchproxy.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 8b 4d d0 48 8d 0c d1 4c 8b 7d c8 48 09 01 48 8b 5d c0 48 8b 43 30 4c 89 e9 48 c1 e1 04 4c 89 34 08 4c 89 64 08 08 49 c1 e5 05 4c 03 6b 38 4c 8d b5 50 ff ff ff 4c 89 f7 4c 89 ee e8 b5 96 ff ff 4c 89 f7 e8 8d 96 ff ff 48 8b 43 10 48 ff c0 70 4f 48 8b 4d a8 48 ff c1 48 89 43 10 4c 8b 75 b8 4c 39 f1 4c 8d 65 80 } //01 00 
		$a_00_1 = {45 31 c0 4c 89 f2 4c 89 e1 e8 5a 04 00 00 a8 01 0f 85 c3 00 00 00 49 ff c5 49 21 dd 4c 89 ea 48 c1 ea 06 48 8b 45 d0 48 8b 34 d0 b8 01 00 00 00 44 89 e9 48 d3 e0 4c 0f a3 ee } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}