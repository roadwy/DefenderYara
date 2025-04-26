
rule Trojan_Win32_Zenpak_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {4f 3a 5c 6c 34 68 4e 66 59 41 5c 39 56 6c 5c 36 66 5c 57 5c 38 64 47 4e 61 4f 6d 2e 70 64 62 } //O:\l4hNfYA\9Vl\6f\W\8dGNaOm.pdb  1
		$a_80_1 = {54 70 6f 6e 66 4b 68 65 65 6d } //TponfKheem  1
		$a_80_2 = {45 68 68 65 72 62 4d 69 64 73 74 59 53 63 72 65 70 6c 65 6e 69 73 68 } //EhherbMidstYScreplenish  1
		$a_80_3 = {61 6c 73 6f 68 65 66 69 72 6d 61 6d 65 6e 74 41 39 54 68 65 72 65 66 69 73 68 6b 69 6e 64 } //alsohefirmamentA9Therefishkind  1
		$a_80_4 = {47 4a 6d 65 61 74 67 6f 64 72 43 59 53 73 65 74 41 62 75 6e 64 61 6e 74 6c 79 } //GJmeatgodrCYSsetAbundantly  1
		$a_80_5 = {63 35 66 6f 77 6c 47 62 65 2e 75 4d 6d 64 6f 65 73 6e 2e 74 77 55 } //c5fowlGbe.uMmdoesn.twU  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}