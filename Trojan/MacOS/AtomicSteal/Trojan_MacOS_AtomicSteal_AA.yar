
rule Trojan_MacOS_AtomicSteal_AA{
	meta:
		description = "Trojan:MacOS/AtomicSteal.AA,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5f 6d 65 6d 63 70 79 } //1 _memcpy
		$a_00_1 = {48 89 d1 48 c1 e9 1d 4c 21 e9 48 31 d1 48 89 cf 48 c1 e7 11 49 b8 00 00 00 00 00 78 06 00 4c 21 c7 49 89 c8 49 c1 e0 25 49 b9 00 00 00 00 00 e8 07 00 4d 21 c8 49 31 f8 49 31 d0 49 c1 e8 2b 44 31 c1 32 0c 30 80 c1 05 88 0c 30 48 ff c6 } //1
		$a_00_2 = {48 8d 47 01 48 c1 e8 03 49 f7 e7 48 d1 ea 48 69 c2 38 01 00 00 48 f7 d8 4c 8d 04 07 49 ff c0 49 8b 04 fc 4c 21 f0 44 89 c2 4d 8b 14 d4 45 89 d1 41 81 e1 fe ff ff 7f 49 09 c1 4c 8d 9f 9c 00 00 00 4c 89 d8 48 c1 e8 03 49 f7 e7 d1 ea 69 c2 38 01 00 00 41 29 c3 49 d1 e9 41 f6 c2 01 ba 00 00 00 00 48 0f 45 d3 4b 33 14 dc 4c 31 ca 49 89 14 fc } //1
		$a_00_3 = {5f 73 79 73 74 65 6d } //1 _system
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}