
rule TrojanSpy_AndroidOS_FakeApp_U_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeApp.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {35 77 45 30 61 4d 46 72 47 78 53 48 42 79 35 67 39 78 51 4e 54 51 3d 3d } //1 5wE0aMFrGxSHBy5g9xQNTQ==
		$a_00_1 = {73 4f 34 41 2b 63 55 51 4b 41 74 55 48 35 68 4f 55 51 6b 68 33 50 75 64 73 74 52 39 53 32 73 4f 2f 76 35 63 4e 48 70 53 45 44 69 31 62 61 32 37 58 2b 45 5a 52 67 3d 3d } //1 sO4A+cUQKAtUH5hOUQkh3PudstR9S2sO/v5cNHpSEDi1ba27X+EZRg==
		$a_00_2 = {47 76 72 78 51 4b 2b 41 67 78 4c 38 64 43 51 48 42 66 4d 67 57 67 3d 3d } //1 GvrxQK+AgxL8dCQHBfMgWg==
		$a_00_3 = {4e 54 54 e3 83 89 e3 82 b3 e3 83 a2 } //1
		$a_00_4 = {6f 70 65 6e 4c 69 6d 69 74 } //1 openLimit
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}