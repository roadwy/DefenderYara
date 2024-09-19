
rule Trojan_BAT_Redline_VZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {75 57 65 4e 61 53 6a 52 68 68 56 54 73 4f 52 56 69 63 6b 61 63 4f 4d 48 6d } //1 uWeNaSjRhhVTsORVickacOMHm
		$a_81_1 = {55 56 52 51 59 77 43 71 4d 67 4a 57 62 43 55 57 4e 51 61 2e 64 6c 6c } //1 UVRQYwCqMgJWbCUWNQa.dll
		$a_81_2 = {53 7a 59 51 46 68 63 5a 6a 4f 55 76 54 79 4e 7a 73 61 61 59 51 4e 55 4b 63 50 53 6d 2e 64 6c 6c } //1 SzYQFhcZjOUvTyNzsaaYQNUKcPSm.dll
		$a_81_3 = {42 51 79 43 77 51 4e 61 67 7a 5a 48 54 69 5a 4f 43 4e 50 61 57 77 55 61 44 5a 42 57 41 } //1 BQyCwQNagzZHTiZOCNPaWwUaDZBWA
		$a_81_4 = {61 42 67 77 54 43 4e 61 4a 51 4d 4d 4c 4d 55 64 4f 52 70 54 6a 62 4d 42 69 4a 64 56 2e 64 6c 6c } //1 aBgwTCNaJQMMLMUdORpTjbMBiJdV.dll
		$a_81_5 = {52 4b 6b 45 68 53 68 74 56 4c 74 76 66 47 51 42 6e 65 4a 70 4b 46 77 2e 64 6c 6c } //1 RKkEhShtVLtvfGQBneJpKFw.dll
		$a_81_6 = {4e 78 55 4d 77 4f 44 69 43 70 66 76 6b 49 56 4d 43 5a 4c 75 42 44 4e 50 71 77 65 } //1 NxUMwODiCpfvkIVMCZLuBDNPqwe
		$a_81_7 = {48 4a 71 48 66 75 4d 58 64 64 6e 62 42 79 54 7a 54 6d 6b 58 63 46 4f 4e 78 65 53 56 58 } //1 HJqHfuMXddnbByTzTmkXcFONxeSVX
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}