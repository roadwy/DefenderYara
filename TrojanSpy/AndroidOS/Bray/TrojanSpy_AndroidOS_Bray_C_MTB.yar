
rule TrojanSpy_AndroidOS_Bray_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Bray.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {45 52 4d 37 47 77 30 4f 46 44 30 42 43 41 63 46 42 68 59 3d } //1 ERM7Gw0OFD0BCAcFBhY=
		$a_00_1 = {44 67 49 4b 41 67 77 45 50 42 45 49 47 67 3d 3d } //1 DgIKAgwEPBEIGg==
		$a_00_2 = {41 51 77 4b 48 41 41 50 46 31 68 4b 52 68 6f 50 45 45 73 42 43 77 4d 4d 47 67 3d 3d } //1 AQwKHAAPF1hKRhoPEEsBCwMMGg==
		$a_00_3 = {43 68 63 51 47 46 39 4f 54 41 41 45 42 67 30 58 44 77 30 62 45 55 38 58 44 52 56 47 42 51 73 51 45 45 59 4e 46 51 34 4f } //1 ChcQGF9OTAAEBg0XDw0bEU8XDRVGBQsQEEYNFQ4O
		$a_00_4 = {45 52 4d 37 48 52 55 4e 44 41 4d 42 4e 68 6b 48 45 51 6b 42 46 68 49 4b 44 51 73 3d } //1 ERM7HRUNDAMBNhkHEQkBFhIKDQs=
		$a_00_5 = {4d 51 59 4b 44 43 59 4f 44 52 59 45 43 68 30 77 42 67 63 4e 44 42 63 47 45 41 3d 3d } //1 MQYKDCYODRYECh0wBgcNDBcGEA==
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}