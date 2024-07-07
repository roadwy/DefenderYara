
rule Trojan_Win64_CobaltStrike_NV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {c5 fe 6f 0a c5 fe 6f 52 20 c5 fe 6f 5a 40 c5 fe 6f 62 60 c5 fd 7f 09 c5 fd 7f 51 20 c5 fd 7f 59 40 c5 fd 7f 61 60 c5 fe 6f 8a 80 00 00 00 c5 fe 6f 92 a0 00 00 00 c5 fe 6f 9a c0 00 00 00 c5 fe 6f a2 e0 00 00 00 c5 fd 7f 89 80 00 00 00 c5 fd 7f 91 a0 00 00 00 c5 fd 7f 99 c0 00 00 00 c5 fd 7f a1 e0 00 00 00 48 81 c1 00 01 00 00 48 81 c2 00 01 00 00 49 81 e8 00 01 00 00 49 81 f8 00 01 00 00 0f 83 78 ff ff ff } //5
		$a_01_1 = {c4 a1 7e 6f 4c 0a c0 c4 a1 7e 7f 4c 09 c0 c4 a1 7e 7f 6c 01 e0 c5 fe 7f 00 c5 f8 77 c3 } //5
		$a_01_2 = {c7 44 24 48 00 40 00 00 c7 44 24 4c 00 00 00 00 48 8b 44 24 58 48 89 44 24 50 48 8d 4c 24 38 e8 } //1
		$a_01_3 = {5a 00 3a 00 5c 00 6c 00 69 00 62 00 73 00 5c 00 5a 00 42 00 61 00 72 00 5c 00 7a 00 62 00 61 00 72 00 5c 00 72 00 65 00 66 00 63 00 6e 00 74 00 2e 00 68 00 } //1 Z:\libs\ZBar\zbar\refcnt.h
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}