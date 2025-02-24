
rule Trojan_Win32_Neoreblamy_BAJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0c 00 00 "
		
	strings :
		$a_01_0 = {75 6a 64 6c 5a 4e 45 4c 6f 71 63 44 71 68 4a 61 68 6a 54 6b 76 6a 75 } //3 ujdlZNELoqcDqhJahjTkvju
		$a_01_1 = {6c 6a 54 71 66 41 7a 54 46 73 4c 7a 4e 70 6e 43 44 67 46 73 64 52 4a 6a 58 43 67 75 47 64 } //1 ljTqfAzTFsLzNpnCDgFsdRJjXCguGd
		$a_01_2 = {6b 70 47 63 65 4d 4d 53 4d 6b 59 6d 70 46 71 62 6b 76 58 42 44 54 5a 47 79 52 48 4d } //1 kpGceMMSMkYmpFqbkvXBDTZGyRHM
		$a_01_3 = {79 46 79 53 4c 72 71 52 4b 54 57 55 69 43 50 4c 57 4b 72 65 48 61 57 48 68 69 6c 68 59 } //3 yFySLrqRKTWUiCPLWKreHaWHhilhY
		$a_01_4 = {76 77 72 45 56 46 56 52 54 45 65 77 43 4e 56 65 68 68 73 53 6f 44 6c 78 51 52 43 47 4b 67 } //1 vwrEVFVRTEewCNVehhsSoDlxQRCGKg
		$a_01_5 = {68 54 6c 4f 61 59 50 70 49 43 45 41 65 57 56 61 4a 5a 78 42 54 73 55 78 53 66 67 56 49 6a } //1 hTlOaYPpICEAeWVaJZxBTsUxSfgVIj
		$a_01_6 = {6e 45 59 4c 72 4c 71 74 79 42 66 79 52 4b 53 77 68 73 54 4a 72 6d 44 59 72 48 65 72 43 56 } //3 nEYLrLqtyBfyRKSwhsTJrmDYrHerCV
		$a_01_7 = {78 7a 53 63 52 43 6a 5a 45 68 53 47 52 4d 72 4f 62 58 65 4c 4f 70 70 55 6f 69 74 74 } //1 xzScRCjZEhSGRMrObXeLOppUoitt
		$a_01_8 = {65 68 57 6f 67 59 59 6f 49 4c 66 7a 74 6d 72 6f 6e 53 4e 5a 64 4c 6a 56 71 71 44 45 76 6f 50 4d 71 76 } //1 ehWogYYoILfztmronSNZdLjVqqDEvoPMqv
		$a_01_9 = {46 47 6f 47 61 49 61 49 5a 76 46 42 4e 65 76 4a 57 4e 59 62 79 76 41 } //3 FGoGaIaIZvFBNevJWNYbyvA
		$a_01_10 = {47 55 56 77 76 77 77 68 70 47 54 53 6c 51 6f 52 7a 49 74 7a 4d 66 59 67 6c } //1 GUVwvwwhpGTSlQoRzItzMfYgl
		$a_01_11 = {51 70 73 51 58 79 4d 67 52 72 4d 41 52 7a 51 5a 56 46 57 70 44 57 63 57 4a 6f 69 51 46 76 49 6b 71 6d 48 63 4e 61 4a 59 52 61 76 4a 4e 45 78 70 6b 62 4e 45 4e 78 4a 63 50 75 76 74 64 76 48 63 74 55 76 52 76 63 4f 6c 41 64 5a 67 6f 70 6d 46 66 44 69 6b 65 42 74 4b 65 } //1 QpsQXyMgRrMARzQZVFWpDWcWJoiQFvIkqmHcNaJYRavJNExpkbNENxJcPuvtdvHctUvRvcOlAdZgopmFfDikeBtKe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*3+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=5
 
}