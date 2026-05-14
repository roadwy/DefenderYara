
rule Trojan_Win64_Tedy_SXF_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 51 ff 44 0f b6 84 0c 9f 01 00 00 83 e2 06 44 32 44 14 20 41 80 f0 aa 44 88 44 01 ff 48 83 f9 17 74 72 0f b6 94 0c a0 01 00 00 41 89 c8 41 83 e0 07 42 32 54 04 20 80 f2 aa 88 14 01 48 83 c1 02 eb bd } //20
		$a_01_1 = {44 0f b6 8c 15 00 d2 3c 00 44 8d 52 0f 85 d2 44 0f 49 d2 41 83 e2 f0 41 89 d3 45 29 d3 46 0f b6 94 1d 90 d1 3c 00 45 0f b6 c0 4d 01 c8 4d 01 d0 45 0f b6 d0 46 0f b6 9c 15 00 d2 3c 00 44 88 9c 15 00 d2 3c 00 46 88 8c 15 00 d2 3c 00 48 ff c2 48 81 fa 00 01 00 00 75 a7 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}