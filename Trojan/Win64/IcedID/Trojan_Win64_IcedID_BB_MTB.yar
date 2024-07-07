
rule Trojan_Win64_IcedID_BB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 86 90 01 04 41 2b cb 01 86 90 01 04 03 cf 01 8e 90 01 04 8b 8e 90 01 04 8b 86 90 01 04 44 8b 96 90 01 04 2b c2 05 90 01 04 01 06 b8 90 01 04 2b c1 2b c3 01 46 90 01 01 8d 41 90 01 01 31 86 90 01 04 49 81 f9 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_BB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 30 48 8d 44 01 18 eb dd 48 8b 54 24 28 4c 8b 84 24 c0 01 00 00 66 3b f6 74 0d 48 8b c1 48 89 44 24 30 66 3b ed 74 1f 41 8a 04 00 88 04 0a e9 } //3
		$a_01_1 = {79 68 61 75 64 69 6a 6d 64 73 69 66 75 68 79 61 73 64 69 6a 61 6b 64 73 6d 6a 64 73 75 68 66 79 61 } //1 yhaudijmdsifuhyasdijakdsmjdsuhfya
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_Win64_IcedID_BB_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 01 c0 44 01 e0 44 29 f8 48 98 32 14 06 48 8b 44 24 90 01 01 88 14 38 48 39 5c 24 90 01 01 48 8d 43 01 48 89 44 24 90 01 01 90 13 8b 0d 90 01 04 44 8b 15 90 01 04 44 8b 05 90 01 04 44 8b 0d 90 01 04 44 8b 1d 90 01 04 8b 35 90 01 04 89 c8 44 89 d7 41 0f af c2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}