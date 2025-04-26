
rule Trojan_Win64_Cobaltstrike_DV_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 d1 48 8b ca 48 33 c8 48 8b c1 48 0f be 4c 24 30 48 33 c8 48 8b c1 48 8b 8c 24 f0 00 00 00 88 84 0c ac 00 00 00 e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Cobaltstrike_DV_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 60 49 03 c2 42 0f b6 0c 18 b8 ?? ?? ?? ?? 44 03 c1 48 8b 8c 24 ?? ?? ?? ?? 41 f7 e8 41 03 d0 c1 fa 0d 8b c2 c1 e8 1f 03 d0 69 d2 ?? ?? ?? ?? 44 2b c2 49 63 c0 48 03 44 24 70 49 03 c5 48 03 c6 42 0f b6 04 18 30 04 0b } //1
		$a_81_1 = {3e 65 41 29 23 4f 6f 4f 6a 41 50 56 65 73 50 61 32 4c 44 28 75 7a 34 44 36 3c 74 26 74 66 48 48 49 55 6e 75 47 67 75 6e 57 44 49 51 45 52 6b 43 45 4e 40 72 46 59 50 65 63 5a 5f 41 62 65 43 7a 45 45 57 68 68 34 48 5a 70 45 47 48 48 74 57 77 3e 78 33 24 75 23 44 78 5a 46 75 69 62 6d 44 4c 52 62 67 31 66 76 2a 34 40 } //1 >eA)#OoOjAPVesPa2LD(uz4D6<t&tfHHIUnuGgunWDIQERkCEN@rFYPecZ_AbeCzEEWhh4HZpEGHHtWw>x3$u#DxZFuibmDLRbg1fv*4@
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}