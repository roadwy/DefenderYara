
rule Trojan_Win32_Stealc_GMF_MTB{
	meta:
		description = "Trojan:Win32/Stealc.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 51 63 75 68 37 4e 71 42 6a 36 68 61 62 6b 73 73 6b 7a 39 42 49 64 66 48 66 69 54 } //01 00  yQcuh7NqBj6habksskz9BIdfHfiT
		$a_01_1 = {69 6b 51 38 7a 4f 59 73 54 42 73 3d } //01 00  ikQ8zOYsTBs=
		$a_01_2 = {74 55 34 37 79 75 41 78 59 54 4f 70 62 34 77 6e 6b 42 47 6b 55 65 73 59 62 66 55 3d } //01 00  tU47yuAxYTOpb4wnkBGkUesYbfU=
		$a_01_3 = {77 31 38 39 6b 61 41 30 51 48 58 68 59 71 30 3d } //01 00  w189kaA0QHXhYq0=
		$a_01_4 = {70 51 30 55 37 76 63 7a 55 69 69 6c 5a 35 77 70 6f 68 6d 55 } //00 00  pQ0U7vczUiilZ5wpohmU
	condition:
		any of ($a_*)
 
}