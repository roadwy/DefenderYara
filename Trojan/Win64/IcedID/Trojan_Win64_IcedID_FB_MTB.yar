
rule Trojan_Win64_IcedID_FB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 77 75 69 6a 6b 61 6d 64 73 6a 75 69 6a 61 } //01 00  ewuijkamdsjuija
		$a_01_1 = {66 54 6d 76 41 44 4b 51 } //01 00  fTmvADKQ
		$a_01_2 = {67 39 58 63 36 6f 73 39 4b 4c } //01 00  g9Xc6os9KL
		$a_01_3 = {69 4e 38 73 4d 38 74 } //01 00  iN8sM8t
		$a_01_4 = {6c 61 75 30 32 73 31 37 } //00 00  lau02s17
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_FB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {3a c0 74 d8 44 89 4c 24 20 4c 89 44 24 18 66 3b d2 74 12 83 44 24 40 08 c7 44 24 44 1b 00 00 00 66 3b f6 74 a5 48 89 54 24 10 48 89 4c 24 08 3a e4 74 00 48 81 ec 68 02 00 00 c7 44 24 30 6e 00 00 00 3a ed 0f 84 4c ff ff ff } //02 00 
		$a_01_1 = {6e 74 61 67 73 68 6a 6a 61 73 68 67 64 61 61 } //00 00  ntagshjjashgdaa
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_FB_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 77 37 4b 35 30 6a 6d 6c 77 57 4f 37 4d 4a 52 38 44 44 37 48 56 4c 70 61 55 } //01 00  Cw7K50jmlwWO7MJR8DD7HVLpaU
		$a_01_1 = {47 55 6a 61 62 68 73 75 66 79 75 61 73 6b 6a 6e 61 6b 73 6b 66 6a 73 61 } //01 00  GUjabhsufyuaskjnakskfjsa
		$a_01_2 = {4a 57 6e 66 6e 33 58 76 6c 75 63 63 53 4b 6c 48 36 6a 64 47 4b 6f 66 43 32 33 6c } //01 00  JWnfn3XvluccSKlH6jdGKofC23l
		$a_01_3 = {4b 48 49 6b 4c 6b 58 74 6f 4c 6d 61 66 74 43 51 49 46 36 69 38 47 6c } //01 00  KHIkLkXtoLmaftCQIF6i8Gl
		$a_01_4 = {4b 59 41 74 68 62 64 64 4f 78 54 62 61 6c 51 68 6a 43 } //00 00  KYAthbddOxTbalQhjC
	condition:
		any of ($a_*)
 
}