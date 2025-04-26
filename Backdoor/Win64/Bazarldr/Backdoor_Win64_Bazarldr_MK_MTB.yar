
rule Backdoor_Win64_Bazarldr_MK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af d0 89 d0 44 31 f8 25 [0-04] bd [0-04] 21 ea 09 c2 89 d0 31 e8 83 e0 fe 81 f2 [0-04] 09 c2 44 39 fa 0f 94 c0 0f 95 c2 83 f9 [0-01] 0f 9c c3 83 f9 [0-01] 0f 9f c1 20 c8 08 d1 20 d3 08 c3 89 c8 30 d8 b8 [0-04] ba [0-04] 0f 45 c2 84 db 89 c5 ba [0-04] 0f 45 ea 48 89 74 24 70 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Backdoor_Win64_Bazarldr_MK_MTB_2{
	meta:
		description = "Backdoor:Win64/Bazarldr.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 20 44 8b cb 44 8b c0 33 c9 ff 15 [0-04] 48 8b d8 44 8b 44 24 [0-01] 48 8b d7 48 8b c8 e8 [0-03] 00 } //1
		$a_03_1 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-01] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4 } //1
		$a_03_2 = {41 0f b6 00 48 ff c1 49 ff c8 48 3b cb 42 88 44 21 [0-01] 7c ec } //1
		$a_03_3 = {8b 06 48 8b 4c 24 [0-01] 45 33 c9 89 44 24 [0-01] 45 8d 41 [0-01] 33 d2 48 89 74 24 [0-01] 48 89 6c 24 [0-01] ff 15 [0-04] 85 c0 0f 95 c0 eb bd } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}