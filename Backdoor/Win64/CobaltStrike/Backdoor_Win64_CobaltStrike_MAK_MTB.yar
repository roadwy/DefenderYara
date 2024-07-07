
rule Backdoor_Win64_CobaltStrike_MAK_MTB{
	meta:
		description = "Backdoor:Win64/CobaltStrike.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 3b c6 0f b6 04 28 41 88 42 ff 72 90 0a 50 00 b8 90 02 04 41 8b c8 47 88 04 11 49 83 c2 01 41 f7 e0 2b ca 41 8b c0 d1 e9 41 83 c0 01 03 ca c1 e9 90 02 01 6b c9 90 02 01 2b c1 90 00 } //1
		$a_03_1 = {45 0f b6 01 43 0f be 0c 0b b8 90 02 04 03 cf 49 83 c1 01 41 03 c8 8b f9 f7 e1 c1 ea 90 02 01 69 d2 90 02 04 2b fa 48 83 ee 01 48 63 cf 0f b6 04 19 41 88 41 ff 44 88 04 19 75 90 00 } //1
		$a_03_2 = {83 c3 01 b8 90 02 04 45 8b c3 45 2b c5 41 83 c3 01 f7 e3 c1 ea 90 02 01 b8 90 02 04 69 d2 90 02 04 2b da 4c 63 d3 45 0f b6 0c 3a 45 03 e1 41 f7 e4 c1 ea 90 02 01 69 d2 90 02 04 44 2b e2 49 63 cc 0f b6 04 39 41 88 04 3a 44 88 0c 39 41 0f b6 0c 3a 41 03 c9 b8 90 02 04 f7 e1 c1 ea 90 02 01 69 d2 90 02 04 2b ca 48 63 c1 0f b6 0c 38 41 30 0c 30 48 83 ed 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}