
rule Trojan_Win64_IcedID_DK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {80 44 04 28 f5 48 ff c0 48 83 f8 04 75 f2 48 8d 5c 24 30 48 8d 54 24 28 41 b8 04 00 00 00 48 89 d9 } //03 00 
		$a_80_1 = {4a 43 4e 45 56 36 64 38 6c 79 50 49 52 65 5a 63 44 59 46 38 46 32 6a 53 48 55 37 55 } //JCNEV6d8lyPIReZcDYF8F2jSHU7U  03 00 
		$a_80_2 = {64 6d 62 41 39 73 64 30 54 4b 42 63 4a 6f 37 34 64 4f 76 63 72 6b } //dmbA9sd0TKBcJo74dOvcrk  03 00 
		$a_80_3 = {6b 54 65 6e 51 58 67 50 32 74 63 44 36 76 32 37 34 } //kTenQXgP2tcD6v274  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DK_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0c 00 00 0a 00 "
		
	strings :
		$a_01_0 = {62 73 74 62 53 70 2e 64 6c 6c } //01 00  bstbSp.dll
		$a_01_1 = {42 65 67 62 6e 61 66 52 6c 65 46 } //01 00  BegbnafRleF
		$a_01_2 = {44 61 43 71 45 64 6b 4c 41 76 } //01 00  DaCqEdkLAv
		$a_01_3 = {50 77 51 4a 67 4e 67 71 48 57 } //0a 00  PwQJgNgqHW
		$a_01_4 = {65 56 45 39 79 4c 2e 64 6c 6c } //01 00  eVE9yL.dll
		$a_01_5 = {41 74 62 4d 42 75 66 6c 78 46 } //01 00  AtbMBuflxF
		$a_01_6 = {42 69 6f 6e 6b 63 73 7a 65 77 62 } //01 00  Bionkcszewb
		$a_01_7 = {57 79 54 75 42 56 66 4d 52 71 } //0a 00  WyTuBVfMRq
		$a_01_8 = {63 47 71 75 4c 45 4a 37 78 56 2e 64 6c 6c } //01 00  cGquLEJ7xV.dll
		$a_01_9 = {6c 48 54 57 73 4f 4a 78 4a } //01 00  lHTWsOJxJ
		$a_01_10 = {6e 61 74 79 57 4a 44 43 69 42 } //01 00  natyWJDCiB
		$a_01_11 = {6d 6f 5a 78 73 6a 56 69 73 59 } //00 00  moZxsjVisY
	condition:
		any of ($a_*)
 
}